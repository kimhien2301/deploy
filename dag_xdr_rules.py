"""
=====================================================================
DAG 2: XDR Rules Sync → TimescaleDB
=====================================================================

Schedule: Mỗi 6 giờ
Tasks:
  1. sync_bioc_rules        — BIOC Rules → device_rules + device_rule_items
  2. sync_correlation_rules — Correlation Rules → device_rules + device_rule_items
  3. sync_detection_rules   — Detection Rules (CSPM) → device_rules + device_rule_items

Hash-based change detection: chỉ insert khi có thay đổi.
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator

import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xdr_common.api_client import XDRClient
from xdr_common.db_writer import upsert_device_rules, insert_rule_items

logger = logging.getLogger(__name__)

SOURCE = "cortex_xdr"


# ======================================================================
# TASK FUNCTIONS
# ======================================================================

def sync_bioc_rules(**context):
    """Sync BIOC rules: fetch → hash check → upsert."""
    client = XDRClient()
    rules = client.get_bioc_rules()
    logger.info(f"Fetched {len(rules)} BIOC rules")

    snapshot_id = upsert_device_rules(SOURCE, "bioc_rules", rules)
    if snapshot_id:
        insert_rule_items(
            snapshot_id=snapshot_id,
            source=SOURCE,
            rules=rules,
            rule_type_name="bioc",
            id_field="rule_id",
            name_field="name",
            severity_field="severity",
            enabled_field="status",
        )


def sync_correlation_rules(**context):
    """Sync Correlation rules: fetch → hash check → upsert."""
    client = XDRClient()
    rules = client.get_correlation_rules()
    logger.info(f"Fetched {len(rules)} Correlation rules")

    snapshot_id = upsert_device_rules(SOURCE, "correlation_rules", rules)
    if snapshot_id:
        insert_rule_items(
            snapshot_id=snapshot_id,
            source=SOURCE,
            rules=rules,
            rule_type_name="correlation",
            id_field="id",
            name_field="name",
            severity_field="severity",
            enabled_field="is_enabled",
        )


def sync_detection_rules(**context):
    """Sync Detection Rules (CSPM): fetch → hash check → upsert."""
    client = XDRClient()
    rules = client.get_detection_rules()
    logger.info(f"Fetched {len(rules)} Detection rules")

    if not rules:
        logger.warning("Detection rules empty (may need Pro license)")
        return

    snapshot_id = upsert_device_rules(SOURCE, "detection_cspm", rules)
    if snapshot_id:
        insert_rule_items(
            snapshot_id=snapshot_id,
            source=SOURCE,
            rules=rules,
            rule_type_name="detection_cspm",
            id_field="id",
            name_field="name",
            severity_field="severity",
            enabled_field="enabled",
        )


# ======================================================================
# DAG DEFINITION
# ======================================================================

default_args = {
    "owner": "soc-data-engineering",
    "depends_on_past": False,
    "email_on_failure": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=5),
}

with DAG(
    dag_id="xdr_rules_sync",
    default_args=default_args,
    description="Cortex XDR Rules → device_rules + device_rule_items (BIOC, Correlation, Detection)",
    schedule_interval="0 */6 * * *",
    start_date=datetime(2026, 4, 27),
    catchup=False,
    max_active_runs=1,
    tags=["xdr", "rules", "config", "soc"],
) as dag:

    t_bioc = PythonOperator(
        task_id="sync_bioc_rules",
        python_callable=sync_bioc_rules,
    )

    t_corr = PythonOperator(
        task_id="sync_correlation_rules",
        python_callable=sync_correlation_rules,
    )

    t_det = PythonOperator(
        task_id="sync_detection_rules",
        python_callable=sync_detection_rules,
    )

    # Chạy song song
    [t_bioc, t_corr, t_det]
