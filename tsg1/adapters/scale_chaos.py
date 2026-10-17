"""Adapters for Scale/Chaos run-first smoke scenarios (SC-*).

These require a running stack (PostgreSQL / NATS JetStream / MinIO, via
docker-compose) and sustained load or fault injection. None of that is
provisioned in this offline harness, so each is reported NOT_RUN with the
precise prerequisite rather than a fabricated SLO pass.
"""
from __future__ import annotations

from ._evidence import make_unavailable_adapter as _na

SC_UNAVAILABLE: dict[str, str] = {
    "SC-001": "requires running ingest stack + load generator to measure "
              ">=2000 events/sec (docker-compose not provisioned offline)",
    "SC-004": "requires `docker compose up` cold-start timing (stack not "
              "provisioned offline)",
    "SC-010": "requires a running PostgreSQL to kill mid-incident (chaos; "
              "stack not provisioned offline)",
    "SC-011": "requires a running NATS JetStream to kill mid-stream (chaos)",
    "SC-012": "requires a running MinIO to kill mid-write (chaos)",
}

for _sid, _reason in SC_UNAVAILABLE.items():
    _na(_sid, _reason)
