"""
device_registry.py — SQLite-backed device registry.

Tracks all provisioned devices, their certificate serials, expiry dates,
and revocation status. The registry is consulted by the provisioning tool
and can be queried by ops scripts to identify expiring or revoked devices.
"""

import sqlite3
import datetime
from pathlib import Path


DDL = """
CREATE TABLE IF NOT EXISTS devices (
    device_id     TEXT PRIMARY KEY,
    cert_serial   TEXT NOT NULL UNIQUE,
    provisioned_at TEXT NOT NULL,
    not_after      TEXT NOT NULL,
    revoked        INTEGER NOT NULL DEFAULT 0,
    revoked_at     TEXT,
    token_hash     TEXT
);

CREATE INDEX IF NOT EXISTS idx_serial ON devices(cert_serial);
CREATE INDEX IF NOT EXISTS idx_revoked ON devices(revoked);
"""


class DeviceRegistry:
    def __init__(self, db_path: str = "pki/devices.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(DDL)
        self._conn.commit()

    def register(self, device_id: str, serial: str, not_after: str, token_hash: str) -> None:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO devices (device_id, cert_serial, provisioned_at, not_after, token_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (device_id, serial, now, not_after, token_hash),
        )
        self._conn.commit()

    def revoke(self, device_id: str) -> bool:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cur = self._conn.execute(
            "UPDATE devices SET revoked=1, revoked_at=? WHERE device_id=? AND revoked=0",
            (now, device_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def exists(self, device_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM devices WHERE device_id=? AND revoked=0", (device_id,)
        ).fetchone()
        return row is not None

    def is_revoked_serial(self, serial: str) -> bool:
        row = self._conn.execute(
            "SELECT revoked FROM devices WHERE cert_serial=?", (serial,)
        ).fetchone()
        return bool(row and row["revoked"])

    def get(self, device_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM devices WHERE device_id=?", (device_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_expiring(self, within_days: int = 30) -> list[dict]:
        """Return devices whose certs expire within within_days."""
        cutoff = (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=within_days)
        ).isoformat()
        rows = self._conn.execute(
            "SELECT * FROM devices WHERE not_after <= ? AND revoked=0", (cutoff,)
        ).fetchall()
        return [dict(r) for r in rows]

    def export_revoked_serials(self) -> list[str]:
        """Return all revoked certificate serials for CRL/OCSP generation."""
        rows = self._conn.execute(
            "SELECT cert_serial FROM devices WHERE revoked=1"
        ).fetchall()
        return [r["cert_serial"] for r in rows]
