"""
=====================================================================
DB Writer — Ghi dữ liệu vào TimescaleDB
=====================================================================

Batch INSERT vào:
  - ocsf_events (hypertable)
  - device_rules + device_rule_items (rules snapshot)
  - asset_registry (MAC-based endpoint registry)

Dùng Airflow PostgresHook hoặc psycopg2 trực tiếp.
"""

import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _get_connection():
    """Lấy connection từ Airflow hoặc fallback psycopg2."""
    try:
        from airflow.providers.postgres.hooks.postgres import PostgresHook
        hook = PostgresHook(postgres_conn_id="timescaledb_default")
        return hook.get_conn()
    except Exception:
        import psycopg2
        return psycopg2.connect(
            host="localhost",
            port=5432,
            dbname="soc_datalake",
            user="airflow_writer",
            password="changeme",
        )


# ======================================================================
# OCSF EVENTS — Batch INSERT
# ======================================================================

# Columns matching ocsf_events table
OCSF_COLUMNS = [
    "time", "class_uid", "class_name", "category_uid", "category_name",
    "severity_id", "severity", "activity_id", "activity_name",
    "status_id", "status", "event_classification",
    "finding_title", "finding_desc", "finding_uid", "finding_types",
    "src_ip", "src_port", "src_hostname", "src_mac",
    "dst_ip", "dst_port", "dst_hostname",
    "user_name", "process_name", "process_cmd_line", "parent_process_name",
    "file_name", "file_path", "file_hash",
    "product_name", "product_vendor", "log_source", "log_source_id",
    "action", "action_id", "count",
    "enrichment", "ocsf_json",
]


def insert_ocsf_events(rows: List[Dict[str, Any]]) -> int:
    """
    Batch INSERT rows vào ocsf_events hypertable.
    Returns: number of rows inserted.
    """
    if not rows:
        return 0

    conn = _get_connection()
    cur = conn.cursor()

    # Build parameterized INSERT
    cols = ", ".join(OCSF_COLUMNS)
    placeholders = ", ".join(["%s"] * len(OCSF_COLUMNS))
    sql = f"INSERT INTO ocsf_events ({cols}) VALUES ({placeholders})"

    batch = []
    for row in rows:
        values = []
        for col in OCSF_COLUMNS:
            val = row.get(col)
            # Handle special types
            if col == "finding_types" and isinstance(val, list):
                val = val  # psycopg2 handles list → TEXT[]
            elif col in ("enrichment", "ocsf_json") and isinstance(val, str):
                pass  # already JSON string
            elif col in ("enrichment", "ocsf_json") and isinstance(val, dict):
                val = json.dumps(val, ensure_ascii=False, default=str)
            values.append(val)
        batch.append(tuple(values))

    try:
        cur.executemany(sql, batch)
        conn.commit()
        count = len(batch)
        logger.info(f"Inserted {count} rows into ocsf_events")
        return count
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to insert ocsf_events: {e}")
        raise
    finally:
        cur.close()
        conn.close()


# ======================================================================
# DEVICE RULES — Snapshot INSERT + Flatten to Items
# ======================================================================

def upsert_device_rules(
    source: str,
    rule_type: str,
    rules_data: List[Dict[str, Any]],
) -> Optional[int]:
    """
    INSERT snapshot vào device_rules.
    Kiểm tra hash — skip nếu không thay đổi.
    Trả về snapshot_id nếu có thay đổi, None nếu skip.
    """
    # Compute hash
    data_str = json.dumps(rules_data, sort_keys=True, ensure_ascii=False, default=str)
    data_hash = hashlib.sha256(data_str.encode("utf-8")).hexdigest()

    conn = _get_connection()
    cur = conn.cursor()

    try:
        # Check last hash
        cur.execute(
            "SELECT data_hash FROM device_rules WHERE source = %s AND rule_type = %s "
            "ORDER BY collected_at DESC LIMIT 1",
            (source, rule_type),
        )
        last = cur.fetchone()
        has_changes = (last is None) or (last[0] != data_hash)

        if not has_changes:
            logger.info(f"device_rules [{source}/{rule_type}]: no changes, skipping")
            cur.close()
            conn.close()
            return None

        # Insert new snapshot
        cur.execute(
            "INSERT INTO device_rules (source, rule_type, has_changes, data_hash, rules_count, rules_data) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (source, rule_type, has_changes, data_hash, len(rules_data),
             json.dumps(rules_data, ensure_ascii=False, default=str)),
        )
        snapshot_id = cur.fetchone()[0]
        conn.commit()
        logger.info(f"device_rules [{source}/{rule_type}]: inserted snapshot #{snapshot_id} ({len(rules_data)} rules)")
        return snapshot_id

    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to upsert device_rules: {e}")
        raise
    finally:
        cur.close()
        conn.close()


def insert_rule_items(
    snapshot_id: int,
    source: str,
    rules: List[Dict[str, Any]],
    rule_type_name: str,
    id_field: str = "rule_id",
    name_field: str = "name",
    severity_field: str = "severity",
    enabled_field: str = "status",
) -> int:
    """Flatten rules vào device_rule_items."""
    if not rules:
        return 0

    conn = _get_connection()
    cur = conn.cursor()

    sql = (
        "INSERT INTO device_rule_items "
        "(snapshot_id, source, rule_id, rule_name, rule_type, enabled, severity, description, rule_detail) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )

    batch = []
    for rule in rules:
        rid = str(rule.get(id_field, ""))
        rname = rule.get(name_field, "")
        rsev = rule.get(severity_field, "")

        # Normalize enabled
        enabled_val = rule.get(enabled_field, "")
        if isinstance(enabled_val, bool):
            enabled = enabled_val
        elif isinstance(enabled_val, str):
            enabled = enabled_val.upper() in ("ENABLED", "TRUE", "YES")
        else:
            enabled = True

        desc = rule.get("description", "") or rule.get("comment", "")

        batch.append((
            snapshot_id, source, rid, rname, rule_type_name,
            enabled, rsev, desc,
            json.dumps(rule, ensure_ascii=False, default=str),
        ))

    try:
        cur.executemany(sql, batch)
        conn.commit()
        logger.info(f"Inserted {len(batch)} rule items [{source}/{rule_type_name}]")
        return len(batch)
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to insert rule items: {e}")
        raise
    finally:
        cur.close()
        conn.close()


# ======================================================================
# ASSET REGISTRY — UPSERT (MAC-based, IP history tracking)
# ======================================================================

def upsert_asset_registry(endpoints: List[Dict[str, Any]]) -> int:
    """
    UPSERT endpoints vào asset_registry.
    MAC address = Primary Key (stable identifier cho DHCP).
    Tự động track IP history khi IP thay đổi.
    """
    if not endpoints:
        return 0

    conn = _get_connection()
    cur = conn.cursor()

    # Ensure asset_registry table exists
    cur.execute("""
        CREATE TABLE IF NOT EXISTS asset_registry (
            mac_address         MACADDR       PRIMARY KEY,
            hostname            TEXT          NOT NULL,
            domain              TEXT,
            os_type             TEXT,
            endpoint_type       TEXT,
            endpoint_id         TEXT          UNIQUE,
            current_ip          INET,
            ip_history          JSONB         DEFAULT '[]',
            agent_status        TEXT,
            agent_version       TEXT,
            last_seen           TIMESTAMPTZ,
            first_registered    TIMESTAMPTZ   DEFAULT NOW(),
            last_updated        TIMESTAMPTZ   DEFAULT NOW()
        )
    """)

    upsert_sql = """
        INSERT INTO asset_registry 
            (mac_address, hostname, domain, os_type, endpoint_type, endpoint_id, 
             current_ip, agent_status, agent_version, last_seen, last_updated)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON CONFLICT (mac_address) DO UPDATE SET
            hostname       = EXCLUDED.hostname,
            current_ip     = EXCLUDED.current_ip,
            agent_status   = EXCLUDED.agent_status,
            agent_version  = EXCLUDED.agent_version,
            last_seen      = EXCLUDED.last_seen,
            last_updated   = NOW(),
            ip_history     = CASE
                WHEN asset_registry.current_ip IS DISTINCT FROM EXCLUDED.current_ip
                    AND asset_registry.current_ip IS NOT NULL
                THEN asset_registry.ip_history || jsonb_build_object(
                    'ip', asset_registry.current_ip::text,
                    'from', asset_registry.last_updated::text,
                    'to', NOW()::text
                )
                ELSE asset_registry.ip_history
            END
    """

    inserted = 0
    skipped = 0

    for ep in endpoints:
        # MAC addresses — cần ít nhất 1 MAC
        mac_list = ep.get("mac_address", [])
        if not mac_list:
            skipped += 1
            continue

        # Xử lý endpoint có nhiều MAC (multi-NIC)
        primary_mac = mac_list[0]

        # IP
        ip_list = ep.get("ip", [])
        current_ip = ip_list[0] if ip_list else None

        # OS type normalization
        os_type = ep.get("os_type", "")
        if "WINDOWS" in os_type.upper():
            os_type = "WINDOWS"
        elif "LINUX" in os_type.upper():
            os_type = "LINUX"
        elif "MAC" in os_type.upper():
            os_type = "MACOS"

        # Endpoint type
        etype = ep.get("endpoint_type", "")
        if "SERVER" in etype.upper():
            etype = "server"
        elif "WORKSTATION" in etype.upper():
            etype = "workstation"

        # Last seen
        last_seen = None
        last_seen_raw = ep.get("last_seen")
        if last_seen_raw:
            try:
                last_seen = datetime.fromtimestamp(last_seen_raw / 1000.0, tz=timezone.utc)
            except (OSError, ValueError):
                pass

        try:
            cur.execute(upsert_sql, (
                primary_mac,
                ep.get("endpoint_name", ""),
                ep.get("domain", ""),
                os_type,
                etype,
                ep.get("endpoint_id", ""),
                current_ip,
                ep.get("endpoint_status", ""),
                ep.get("endpoint_version", ""),
                last_seen,
            ))
            inserted += 1
        except Exception as e:
            logger.warning(f"Failed to upsert endpoint {ep.get('endpoint_name')}: {e}")
            conn.rollback()
            continue

    try:
        conn.commit()
    except Exception:
        conn.rollback()

    logger.info(f"asset_registry: upserted {inserted}, skipped {skipped} (no MAC)")
    cur.close()
    conn.close()
    return inserted
