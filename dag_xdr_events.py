"""
=====================================================================
DAG 1: XDR Events → OCSF → TimescaleDB
=====================================================================

Schedule: Mỗi 5 phút
Tasks:
  1. fetch_and_insert_alerts    — Alerts → OCSF → ocsf_events
  2. fetch_and_insert_incidents — Incidents → OCSF → ocsf_events
  3. fetch_and_insert_audit     — Audit Logs → OCSF → ocsf_events

Incremental: Dùng Airflow Variable lưu last_successful_ts
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.models import Variable

import logging
import sys
import os

# Đảm bảo xdr_common importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xdr_common.api_client import XDRClient
from xdr_common.ocsf_mapper import map_alert_to_ocsf, map_incident_to_ocsf, map_audit_to_ocsf
from xdr_common.db_writer import insert_ocsf_events

logger = logging.getLogger(__name__)


# ======================================================================
# HELPER: Get/Set last run timestamp
# ======================================================================

def _get_last_ts(key: str, default: int = 0) -> int:
    """Đọc timestamp lần chạy cuối từ Airflow Variable."""
    try:
        return int(Variable.get(key, default_var=str(default)))
    except Exception:
        return default


def _set_last_ts(key: str, ts: int):
    """Lưu timestamp lần chạy cuối vào Airflow Variable."""
    Variable.set(key, str(ts))


# ======================================================================
# TASK FUNCTIONS
# ======================================================================

def fetch_and_insert_alerts(**context):
    """Fetch alerts mới, map sang OCSF, insert vào ocsf_events."""
    client = XDRClient()
    last_ts = _get_last_ts("xdr_alerts_last_ts")
    
    logger.info(f"Fetching alerts since {last_ts}...")
    alerts = client.get_alerts_since(since_ts=last_ts)
    logger.info(f"Got {len(alerts)} alerts")

    if not alerts:
        return

    # Map to OCSF
    ocsf_rows = []
    max_ts = last_ts
    for alert in alerts:
        rows = map_alert_to_ocsf(alert)
        ocsf_rows.extend(rows)
        # Track max timestamp for incremental
        det_ts = alert.get("detection_timestamp") or alert.get("local_insert_ts") or 0
        if isinstance(det_ts, (int, float)) and det_ts > max_ts:
            max_ts = int(det_ts)

    # Insert
    count = insert_ocsf_events(ocsf_rows)
    logger.info(f"Inserted {count} OCSF rows from {len(alerts)} alerts")

    # Save watermark (+1ms to avoid re-fetching the last alert)
    if max_ts > last_ts:
        _set_last_ts("xdr_alerts_last_ts", max_ts + 1)


def fetch_and_insert_incidents(**context):
    """Fetch incidents mới, map sang OCSF, insert vào ocsf_events."""
    client = XDRClient()
    last_ts = _get_last_ts("xdr_incidents_last_ts")

    logger.info(f"Fetching incidents since {last_ts}...")
    incidents = client.get_incidents_since(since_ts=last_ts)
    logger.info(f"Got {len(incidents)} incidents")

    if not incidents:
        return

    ocsf_rows = []
    max_ts = last_ts
    for inc in incidents:
        row = map_incident_to_ocsf(inc)
        ocsf_rows.append(row)
        ct = inc.get("creation_time") or 0
        if isinstance(ct, (int, float)) and ct > max_ts:
            max_ts = int(ct)

    count = insert_ocsf_events(ocsf_rows)
    logger.info(f"Inserted {count} OCSF rows from {len(incidents)} incidents")

    if max_ts > last_ts:
        _set_last_ts("xdr_incidents_last_ts", max_ts + 1)


def fetch_and_insert_audit_logs(**context):
    """Fetch audit logs mới, map sang OCSF, insert vào ocsf_events."""
    client = XDRClient()
    last_ts = _get_last_ts("xdr_audit_last_ts")

    logger.info(f"Fetching audit logs since {last_ts}...")
    logs = client.get_audit_logs_since(since_ts=last_ts, limit=5000)
    logger.info(f"Got {len(logs)} audit logs")

    if not logs:
        return

    ocsf_rows = []
    max_ts = last_ts
    for log in logs:
        row = map_audit_to_ocsf(log)
        ocsf_rows.append(row)
        at = log.get("AUDIT_INSERT_TIME") or 0
        if isinstance(at, (int, float)) and at > max_ts:
            max_ts = int(at)

    count = insert_ocsf_events(ocsf_rows)
    logger.info(f"Inserted {count} OCSF rows from {len(logs)} audit logs")

    if max_ts > last_ts:
        _set_last_ts("xdr_audit_last_ts", max_ts + 1)


# ======================================================================
# DAG DEFINITION
# ======================================================================

default_args = {
    "owner": "soc-data-engineering",
    "depends_on_past": False,
    "email_on_failure": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=2),
}

with DAG(
    dag_id="xdr_events_to_ocsf",
    default_args=default_args,
    description="Cortex XDR Events → OCSF → TimescaleDB (Alerts, Incidents, Audit Logs)",
    schedule_interval="*/5 * * * *",
    start_date=datetime(2026, 4, 27),
    catchup=False,
    max_active_runs=1,
    tags=["xdr", "ocsf", "events", "soc"],
) as dag:

    t_alerts = PythonOperator(
        task_id="fetch_and_insert_alerts",
        python_callable=fetch_and_insert_alerts,
    )

    t_incidents = PythonOperator(
        task_id="fetch_and_insert_incidents",
        python_callable=fetch_and_insert_incidents,
    )

    t_audit = PythonOperator(
        task_id="fetch_and_insert_audit_logs",
        python_callable=fetch_and_insert_audit_logs,
    )

    # Chạy song song — không phụ thuộc nhau
    [t_alerts, t_incidents, t_audit]
