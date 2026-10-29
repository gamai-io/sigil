# SIGIL read-only standby (Oracle)

- Host: Oracle, `ubuntu@127.0.0.1`
- Path: `/opt/sigil-replica`
- Source: `https://contabo-vps.tailf8e6be.ts.net:19443/gate`
- Timer: `sigil-replica.timer` (every 5 minutes)
- Store: `/opt/sigil-replica/replica.db`
- Verify: gate Ed25519 public key is stored beside the DB; every sync verifies
  receipt hashes, previous hashes and signatures.

```bash
systemctl status sigil-replica.timer
sudo systemctl start sigil-replica.service
SIGIL_REPLICA_BASE=/opt/sigil-replica /usr/bin/python3 /opt/sigil-replica/remote_replica.py status
```

This is a **read-only standby**, not write HA and not automatic failover. If the
primary is down, the last verified chain remains readable on Oracle. Writes still
require the primary lease.
