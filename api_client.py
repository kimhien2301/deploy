"""
=====================================================================
Cortex XDR API Client — Dùng cho Airflow DAGs
=====================================================================

Reuse Advanced Authentication (SHA-256) logic.
Hỗ trợ:
  - Pagination tự động
  - Incremental fetch (creation_time > last_run)
  - Retry với exponential backoff
  - Đọc credentials từ Airflow Variables

Cach dung:
  from xdr_common.api_client import XDRClient
  client = XDRClient()
  alerts = client.get_alerts_since(last_ts)
"""

import hashlib
import secrets
import string
import time
import logging
import requests
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ======================================================================
# DEFAULT CONFIG (override bằng Airflow Variables)
# ======================================================================
PAGE_SIZE = 100
MAX_RETRIES = 3
RETRY_BACKOFF = 2  # seconds, doubled each retry


def _get_airflow_variable(key: str, default: str) -> str:
    """Đọc Variable từ Airflow, fallback default nếu không có."""
    try:
        from airflow.models import Variable

        return Variable.get(key, default_var=default)
    except Exception:
        return default


class XDRClient:
    """Cortex XDR API Client với Advanced Auth."""

    def __init__(
        self,
        api_key_id: Optional[str] = None,
        api_key: Optional[str] = None,
        fqdn: Optional[str] = None,
    ):
        self.api_key_id = api_key_id or _get_airflow_variable("xdr_api_key_id", "")
        self.api_key = api_key or _get_airflow_variable("xdr_api_key", "")
        self.fqdn = fqdn or _get_airflow_variable("xdr_fqdn", "")
        self.base_url = f"https://{self.fqdn}/public_api/v1"
        self.session = requests.Session()

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def _make_headers(self) -> Dict[str, str]:
        """Tạo headers Advanced Authentication (SHA-256)."""
        nonce = "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(64)
        )
        timestamp = str(int(time.time() * 1000))
        raw = self.api_key + nonce + timestamp
        auth_string = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return {
            "x-xdr-auth-id": self.api_key_id,
            "Authorization": auth_string,
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": timestamp,
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Core API Call (with retry)
    # ------------------------------------------------------------------
    def _api_call(
        self, endpoint: str, payload: Dict[str, Any], timeout: int = 30
    ) -> Dict[str, Any]:
        """Gọi 1 XDR API endpoint với retry logic."""
        url = f"{self.base_url}/{endpoint}"

        for attempt in range(MAX_RETRIES):
            try:
                headers = self._make_headers()
                resp = self.session.post(
                    url, json=payload, headers=headers, timeout=timeout
                )

                if resp.status_code == 429:
                    wait = RETRY_BACKOFF * (2**attempt)
                    logger.warning(f"Rate limited (429). Retry in {wait}s...")
                    time.sleep(wait)
                    continue

                if resp.status_code == 500 and attempt < MAX_RETRIES - 1:
                    wait = RETRY_BACKOFF * (2**attempt)
                    logger.warning(
                        f"Server error (500) on {endpoint}. Retry in {wait}s..."
                    )
                    time.sleep(wait)
                    continue

                if resp.status_code != 200:
                    logger.error(
                        f"API Error {resp.status_code}: {endpoint} → {resp.text[:300]}"
                    )
                    return {
                        "error": f"HTTP {resp.status_code}",
                        "status_code": resp.status_code,
                    }

                return resp.json()

            except requests.exceptions.Timeout:
                logger.warning(f"Timeout on {endpoint} (attempt {attempt + 1})")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_BACKOFF * (2**attempt))
                    continue
                return {"error": "Timeout after retries"}
            except Exception as e:
                logger.error(f"Exception on {endpoint}: {e}")
                return {"error": str(e)}

        return {"error": "Max retries exceeded"}

    # ------------------------------------------------------------------
    # Paginated Fetch (tự động loop qua tất cả pages)
    # ------------------------------------------------------------------
    def _fetch_paginated(
        self,
        endpoint: str,
        payload_base: Dict[str, Any],
        result_key: str,
        page_size: int = PAGE_SIZE,
        max_records: int = 50000,
    ) -> List[Dict[str, Any]]:
        """Fetch tất cả records với auto-pagination."""
        all_records = []
        offset = 0

        while offset < max_records:
            payload = {
                "request_data": {
                    **payload_base,
                    "search_from": offset,
                    "search_to": offset + page_size,
                }
            }
            result = self._api_call(endpoint, payload)

            if "error" in result:
                logger.error(
                    f"Pagination stopped at offset {offset}: {result['error']}"
                )
                break

            reply = result.get("reply", {})
            records = reply.get(result_key, [])

            if not records:
                break

            all_records.extend(records)
            total = reply.get("total_count", 0)
            logger.info(f"  {endpoint}: fetched {len(all_records)}/{total} records")

            if len(records) < page_size or len(all_records) >= total:
                break

            offset += page_size

        return all_records

    # ------------------------------------------------------------------
    # Event APIs (incremental)
    # ------------------------------------------------------------------
    def get_alerts_since(self, since_ts: int = 0) -> List[Dict[str, Any]]:
        """Lấy alerts mới hơn since_ts (epoch ms)."""
        filters = []
        if since_ts > 0:
            filters.append(
                {
                    "field": "creation_time",
                    "operator": "gte",
                    "value": since_ts,
                }
            )
        return self._fetch_paginated(
            "alerts/get_alerts_multi_events",
            {"filters": filters, "sort": {"field": "creation_time", "keyword": "asc"}},
            result_key="alerts",
        )

    def get_incidents_since(self, since_ts: int = 0) -> List[Dict[str, Any]]:
        """Lấy incidents mới hơn since_ts (epoch ms)."""
        filters = []
        if since_ts > 0:
            filters.append(
                {
                    "field": "creation_time",
                    "operator": "gte",
                    "value": since_ts,
                }
            )
        return self._fetch_paginated(
            "incidents/get_incidents/",
            {"filters": filters, "sort": {"field": "creation_time", "keyword": "asc"}},
            result_key="incidents",
        )

    def get_audit_logs_since(
        self, since_ts: int = 0, limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Lấy audit logs mới hơn since_ts (epoch ms)."""
        filters = []
        if since_ts > 0:
            filters.append(
                {
                    "field": "AUDIT_INSERT_TIME",
                    "operator": "gte",
                    "value": since_ts,
                }
            )
        return self._fetch_paginated(
            "audits/management_logs/",
            {"filters": filters},
            result_key="data",
            max_records=limit,
        )

    # ------------------------------------------------------------------
    # Rule APIs (full fetch — no incremental)
    # ------------------------------------------------------------------
    def get_bioc_rules(self) -> List[Dict[str, Any]]:
        """Lấy tất cả BIOC rules."""
        result = self._api_call(
            "bioc/get",
            {"request_data": {"filters": [], "search_from": 0, "search_to": 500}},
        )
        # bioc/get trả về {objects_count, objects, objects_type} — không có reply wrapper
        if "objects" in result:
            return result.get("objects", [])
        elif "reply" in result:
            reply = result["reply"]
            if isinstance(reply, dict):
                return reply.get("objects", [])
            return reply if isinstance(reply, list) else []
        return []

    def get_correlation_rules(self) -> List[Dict[str, Any]]:
        """Lấy tất cả Correlation rules."""
        result = self._api_call(
            "correlations/get",
            {"request_data": {"filters": [], "search_from": 0, "search_to": 500}},
        )
        if "objects" in result:
            return result.get("objects", [])
        elif "reply" in result:
            reply = result["reply"]
            if isinstance(reply, dict):
                return reply.get("objects", [])
            return reply if isinstance(reply, list) else []
        return []

    def get_detection_rules(self) -> List[Dict[str, Any]]:
        """Lấy Detection Rules (rule/search — cần Pro license)."""
        result = self._api_call(
            "rule/search",
            {"request_data": {"filters": [], "search_from": 0, "search_to": 500}},
        )
        if "data" in result:
            return result.get("data", [])
        elif "reply" in result:
            reply = result["reply"]
            if isinstance(reply, dict):
                return reply.get("data", reply.get("rules", []))
            return reply if isinstance(reply, list) else []
        return []

    # ------------------------------------------------------------------
    # Asset API (paginated full fetch)
    # ------------------------------------------------------------------
    def get_all_endpoints(self) -> List[Dict[str, Any]]:
        """Lấy tất cả endpoints (assets) — dùng cho Asset Registry."""
        return self._fetch_paginated(
            "endpoints/get_endpoint/",
            {"filters": []},
            result_key="endpoints",
            max_records=10000,
        )
