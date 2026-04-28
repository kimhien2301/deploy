"""
=====================================================================
OCSF Mapper — Chuyển đổi Cortex XDR data sang OCSF format
=====================================================================

Mapping logic cho 3 loại event:
  1. Alert  → ocsf_events (class_uid=2004, Detection Finding)
  2. Incident → ocsf_events (class_uid=2005, Incident Finding)  
  3. Audit Log → ocsf_events (class_uid=6003, API Activity)

Output: list of dicts matching ocsf_events table columns.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ======================================================================
# SEVERITY MAPPING
# ======================================================================

XDR_SEVERITY_MAP = {
    "informational": (1, "Informational"),
    "info": (1, "Informational"),
    "low": (2, "Low"),
    "medium": (3, "Medium"),
    "med": (3, "Medium"),
    "high": (4, "High"),
    "critical": (5, "Critical"),
    # XDR enum format
    "sev_010_info": (1, "Informational"),
    "sev_020_low": (2, "Low"),
    "sev_030_medium": (3, "Medium"),
    "sev_040_high": (4, "High"),
    "sev_050_critical": (5, "Critical"),
}

AUDIT_SEVERITY_MAP = {
    "SEV_010_INFO": (1, "Informational"),
    "SEV_020_LOW": (2, "Low"),
    "SEV_030_MEDIUM": (3, "Medium"),
    "SEV_040_HIGH": (4, "High"),
    "SEV_050_CRITICAL": (5, "Critical"),
}

# ======================================================================
# ACTION MAPPING
# ======================================================================

XDR_ACTION_MAP = {
    "DETECTED": ("Detected", 1),
    "SCANNED": ("Detected (Scanned)", 1),
    "BLOCKED": ("Blocked", 2),
    "PREVENTED": ("Prevented", 2),
    "REPORTED": ("Reported", 1),
    "QUARANTINED": ("Quarantined", 2),
}


# ======================================================================
# HELPER FUNCTIONS
# ======================================================================

def _epoch_ms_to_dt(epoch_ms: Optional[int]) -> Optional[str]:
    """Convert epoch milliseconds → ISO datetime string."""
    if not epoch_ms or not isinstance(epoch_ms, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc).isoformat()
    except (OSError, ValueError):
        return None


def _parse_severity(severity_raw: Optional[str]) -> tuple:
    """Parse XDR severity → (severity_id, severity_name)."""
    if not severity_raw:
        return (1, "Informational")
    key = str(severity_raw).lower().strip()
    return XDR_SEVERITY_MAP.get(key, (1, "Informational"))


def _safe_ip(ip_val: Any) -> Optional[str]:
    """Extract IP string, handle arrays and None."""
    if ip_val is None:
        return None
    if isinstance(ip_val, list):
        return ip_val[0] if ip_val else None
    return str(ip_val) if ip_val else None


def _parse_mitre(techniques: Optional[list], tactics: Optional[list]) -> dict:
    """Parse MITRE arrays into structured JSONB."""
    result = {}
    if techniques:
        parsed = []
        for t in techniques:
            if " - " in str(t):
                uid, name = str(t).split(" - ", 1)
                parsed.append({"uid": uid.strip(), "name": name.strip()})
            else:
                parsed.append({"uid": str(t), "name": str(t)})
        result["techniques"] = parsed
    if tactics:
        parsed = []
        for t in tactics:
            if " - " in str(t):
                uid, name = str(t).split(" - ", 1)
                parsed.append({"uid": uid.strip(), "name": name.strip()})
            else:
                parsed.append({"uid": str(t), "name": str(t)})
        result["tactics"] = parsed
    return result


# ======================================================================
# ALERT → OCSF (class_uid = 2004, Detection Finding)
# ======================================================================

def map_alert_to_ocsf(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Chuyển 1 XDR Alert → 1+ rows cho ocsf_events.
    
    Mỗi alert có thể chứa nhiều events[] — mỗi event tạo 1 row,
    nhưng chia sẻ alert-level metadata.
    Nếu không có events[], tạo 1 row từ alert-level data.
    """
    rows = []
    sev_id, sev_name = _parse_severity(alert.get("severity"))

    # Alert-level fields
    alert_id = alert.get("alert_id", "")
    detection_ts = alert.get("detection_timestamp")
    alert_name = alert.get("name", "")
    category = alert.get("category", "")
    description = alert.get("description", "")
    source = alert.get("source", "XDR")
    host_name = alert.get("host_name", "")
    host_ip = _safe_ip(alert.get("host_ip"))
    endpoint_id = alert.get("endpoint_id", "")
    action_raw = alert.get("action", "")
    action_pretty, action_id = XDR_ACTION_MAP.get(action_raw, (action_raw, 99))

    # MITRE
    mitre = _parse_mitre(
        alert.get("mitre_technique_id_and_name"),
        alert.get("mitre_tactic_id_and_name"),
    )

    # MAC address
    mac = None
    mac_list = alert.get("mac_addresses") or alert.get("mac")
    if isinstance(mac_list, list) and mac_list:
        mac = mac_list[0]
    elif isinstance(mac_list, str) and mac_list:
        mac = mac_list

    # Nested events
    events = alert.get("events", [])
    if not events:
        events = [{}]  # create 1 row even without nested events

    for evt in events:
        # Extract event-level fields
        src_ip = _safe_ip(evt.get("action_local_ip")) or host_ip
        dst_ip = _safe_ip(evt.get("action_remote_ip"))
        src_port = evt.get("action_local_port")
        dst_port = evt.get("action_remote_port")

        event_time = _epoch_ms_to_dt(evt.get("event_timestamp") or detection_ts)
        if not event_time:
            event_time = _epoch_ms_to_dt(detection_ts)

        # Process info
        process_name = (
            evt.get("actor_process_image_name")
            or evt.get("os_actor_process_image_name")
        )
        process_cmd = (
            evt.get("actor_process_command_line")
            or evt.get("os_actor_process_command_line")
        )
        parent_process = evt.get("causality_actor_process_image_name")
        user_name = evt.get("user_name") or evt.get("os_actor_effective_username")

        # File info
        file_name = evt.get("action_file_name")
        file_hash = evt.get("action_file_sha256") or evt.get("actor_process_image_sha256")
        file_path = evt.get("action_file_path")

        # Build enrichment JSONB
        enrichment = {
            "xdr_alert_id": alert_id,
            "xdr_endpoint_id": endpoint_id,
            "xdr_source": source,
            "xdr_action": action_raw,
            "xdr_resolution_status": alert.get("resolution_status"),
            "xdr_event_type": evt.get("event_type"),
        }
        if mitre:
            enrichment["mitre"] = mitre
        if alert.get("case_id"):
            enrichment["xdr_incident_id"] = str(alert["case_id"])
        if evt.get("fw_app_id"):
            enrichment["fw_app_id"] = evt["fw_app_id"]

        row = {
            "time": event_time,
            "class_uid": 2004,
            "class_name": "Detection Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "severity_id": sev_id,
            "severity": sev_name,
            "activity_id": action_id,
            "activity_name": action_pretty,
            "status_id": 1 if alert.get("resolution_status", "").endswith("NEW") else 2,
            "status": alert.get("resolution_status", ""),
            "event_classification": "alert",
            "finding_title": alert_name,
            "finding_desc": description,
            "finding_uid": str(alert_id),
            "finding_types": [category, source] if category else [source],
            "src_ip": src_ip,
            "src_port": src_port,
            "src_hostname": host_name,
            "src_mac": mac,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "user_name": user_name,
            "process_name": process_name,
            "process_cmd_line": process_cmd,
            "parent_process_name": parent_process,
            "file_name": file_name,
            "file_path": file_path,
            "file_hash": file_hash,
            "product_name": "Cortex XDR",
            "product_vendor": "Palo Alto Networks",
            "log_source": source,
            "log_source_id": endpoint_id,
            "action": action_pretty,
            "action_id": action_id,
            "enrichment": json.dumps(enrichment, ensure_ascii=False),
            "ocsf_json": json.dumps(alert, ensure_ascii=False, default=str),
        }
        rows.append(row)

    return rows


# ======================================================================
# INCIDENT → OCSF (class_uid = 2005)
# ======================================================================

def map_incident_to_ocsf(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Chuyển 1 XDR Incident → 1 row cho ocsf_events."""
    sev_id, sev_name = _parse_severity(incident.get("severity"))
    creation_time = _epoch_ms_to_dt(incident.get("creation_time"))

    # MITRE
    mitre = _parse_mitre(
        incident.get("mitre_techniques_ids_and_names"),
        incident.get("mitre_tactics_ids_and_names"),
    )

    # Hosts parsing: "hostname:endpoint_id"
    hosts = incident.get("hosts", [])
    host_name = ""
    if hosts:
        first_host = hosts[0]
        if ":" in first_host:
            host_name = first_host.split(":")[0]
        else:
            host_name = first_host

    # Enrichment
    enrichment = {
        "xdr_incident_id": incident.get("incident_id"),
        "xdr_url": incident.get("xdr_url"),
        "xdr_alert_count": incident.get("alert_count"),
        "xdr_score": incident.get("aggregated_score"),
        "xdr_assigned_to": incident.get("assigned_user_pretty_name"),
        "xdr_resolve_comment": incident.get("resolve_comment"),
        "xdr_sources": incident.get("incident_sources"),
        "xdr_alert_categories": incident.get("alert_categories"),
    }
    if mitre:
        enrichment["mitre"] = mitre

    # Status mapping
    status_raw = incident.get("status", "")
    status_map = {
        "new": (1, "New"),
        "under_investigation": (2, "In Progress"),
        "resolved_true_positive": (3, "Resolved"),
        "resolved_false_positive": (4, "Suppressed"),
        "resolved_duplicate": (4, "Suppressed"),
        "resolved_other": (3, "Resolved"),
    }
    status_id, status = status_map.get(status_raw, (99, status_raw))

    return {
        "time": creation_time,
        "class_uid": 2005,
        "class_name": "Incident Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "severity_id": sev_id,
        "severity": sev_name,
        "activity_id": 1,
        "activity_name": "Create",
        "status_id": status_id,
        "status": status,
        "event_classification": "offense",
        "finding_title": incident.get("description", ""),
        "finding_desc": incident.get("description", ""),
        "finding_uid": str(incident.get("incident_id", "")),
        "finding_types": incident.get("alert_categories", []),
        "src_hostname": host_name,
        "user_name": incident.get("assigned_user_pretty_name"),
        "product_name": "Cortex XDR",
        "product_vendor": "Palo Alto Networks",
        "log_source": "XDR Incident",
        "count": incident.get("alert_count", 1),
        "enrichment": json.dumps(enrichment, ensure_ascii=False),
        "ocsf_json": json.dumps(incident, ensure_ascii=False, default=str),
    }


# ======================================================================
# AUDIT LOG → OCSF (class_uid = 6003, API Activity)
# ======================================================================

def map_audit_to_ocsf(audit: Dict[str, Any]) -> Dict[str, Any]:
    """Chuyển 1 XDR Audit Log → 1 row cho ocsf_events."""
    sev_id, sev_name = _parse_severity(
        AUDIT_SEVERITY_MAP.get(audit.get("AUDIT_SEVERITY", ""), (1, "Informational"))[1]
    )

    audit_time = _epoch_ms_to_dt(audit.get("AUDIT_INSERT_TIME"))

    # Result → status
    result = audit.get("AUDIT_RESULT", "")
    status_id = 1 if result == "SUCCESS" else 2
    status = "Success" if result == "SUCCESS" else "Failure"

    enrichment = {
        "audit_id": audit.get("AUDIT_ID"),
        "audit_entity": audit.get("AUDIT_ENTITY"),
        "audit_entity_subtype": audit.get("AUDIT_ENTITY_SUBTYPE"),
        "audit_roles": audit.get("AUDIT_USER_ROLES"),
    }

    return {
        "time": audit_time,
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "severity_id": sev_id,
        "severity": sev_name,
        "activity_id": 99,
        "activity_name": audit.get("AUDIT_ENTITY_SUBTYPE", "Other"),
        "status_id": status_id,
        "status": status,
        "event_classification": "event",
        "finding_title": audit.get("AUDIT_ENTITY_SUBTYPE", ""),
        "finding_desc": audit.get("AUDIT_DESCRIPTION", ""),
        "finding_uid": str(audit.get("AUDIT_ID", "")),
        "user_name": audit.get("AUDIT_OWNER_EMAIL", ""),
        "product_name": "Cortex XDR",
        "product_vendor": "Palo Alto Networks",
        "log_source": "XDR Audit",
        "log_source_id": audit.get("AUDIT_ENTITY", ""),
        "enrichment": json.dumps(enrichment, ensure_ascii=False),
        "ocsf_json": json.dumps(audit, ensure_ascii=False, default=str),
    }
