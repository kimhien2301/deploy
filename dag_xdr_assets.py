"""
=====================================================================
DAG 3: XDR Assets Sync → Asset Registry (MAC-based)
=====================================================================

Schedule: Mỗi 1 giờ
Tasks:
  1. fetch_and_upsert_endpoints — Cortex XDR Endpoints → asset_registry

Giải quyết vấn đề DHCP:
  - MAC address = Primary Key (ổn định dù IP đổi)
  - IP history tracking: khi IP thay đổi, IP cũ được lưu vào ip_history JSONB
  - Hostname = cầu nối với QRadar (srcAssetName ↔ endpoint_name)

Xem chi tiết: qradar_log_topology_capability_analysis.md, Section 9-11
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator

import json
import hashlib
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xdr_common.api_client import XDRClient
from xdr_common.db_writer import upsert_asset_registry, upsert_device_rules

logger = logging.getLogger(__name__)

SOURCE = "cortex_xdr"


# ======================================================================
# TASK FUNCTIONS
# ======================================================================


def fetch_and_upsert_endpoints(**context):
    """
    Fetch tất cả endpoints từ Cortex XDR API.
    UPSERT vào asset_registry (MAC = PK).
    Đồng thời lưu snapshot vào device_rules.
    """
    client = XDRClient()
    logger.info("Fetching all XDR endpoints...")
    endpoints = client.get_all_endpoints()
    logger.info(f"Got {len(endpoints)} endpoints")

    if not endpoints:
        logger.warning("No endpoints returned from API")
        return

    # 1. UPSERT vào asset_registry (MAC-based, IP history tracking)
    count = upsert_asset_registry(endpoints)
    logger.info(f"Asset registry: upserted {count} endpoints")

    # 2. Lưu snapshot vào device_rules (cho versioning/change detection)
    snapshot_id = upsert_device_rules(SOURCE, "asset_inventory", endpoints)
    if snapshot_id:
        logger.info(f"Asset snapshot #{snapshot_id} saved ({len(endpoints)} endpoints)")


def log_dhcp_changes(**context):
    """
    (Optional) Query asset_registry để report IP changes gần đây.
    Hữu ích cho SOC analyst theo dõi DHCP churn.
    """
    try:
        from airflow.providers.postgres.hooks.postgres import PostgresHook

        hook = PostgresHook(postgres_conn_id="timescaledb_default")
        conn = hook.get_conn()
        cur = conn.cursor()

        cur.execute("""
            SELECT hostname, mac_address, current_ip, 
                   jsonb_array_length(ip_history) as ip_changes,
                   last_updated
            FROM asset_registry 
            WHERE jsonb_array_length(ip_history) > 0
            ORDER BY last_updated DESC
            LIMIT 20
        """)
        rows = cur.fetchall()

        if rows:
            logger.info("=== DHCP IP Changes (top 20) ===")
            for r in rows:
                logger.info(
                    f"  {r[0]} ({r[1]}) → current: {r[2]}, changes: {r[3]}, last: {r[4]}"
                )
        else:
            logger.info("No DHCP IP changes detected")

        cur.close()
        conn.close()
    except Exception as e:
        logger.warning(f"Could not query DHCP changes: {e}")


# ======================================================================
# DAG DEFINITION
# ======================================================================

default_args = {
    "owner": "soc-data-engineering",
    "depends_on_past": False,
    "email_on_failure": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=3),
}

with DAG(
    dag_id="xdr_assets_sync",
    default_args=default_args,
    description="Cortex XDR Endpoints → asset_registry (MAC-based, DHCP IP tracking)",
    schedule_interval="0 * * * *",
    start_date=datetime(2026, 4, 27),
    catchup=False,
    max_active_runs=1,
    tags=["xdr", "assets", "topology", "dhcp", "soc"],
) as dag:
    t_endpoints = PythonOperator(
        task_id="fetch_and_upsert_endpoints",
        python_callable=fetch_and_upsert_endpoints,
    )

    t_dhcp_report = PythonOperator(
        task_id="log_dhcp_changes",
        python_callable=log_dhcp_changes,
    )

    t_endpoints >> t_dhcp_report
