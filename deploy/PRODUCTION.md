# SIGIL single-node production profile

Scope: hardened **tailnet-only** single-node deployment. This is **not** HA and not a
substitute for an external KMS/HSM or a consensus-replicated gate. Public ingress is
intentionally out of scope.

## Deploy

```bash
cd /opt/sigil
SIGIL_RUNTIME=/opt/sigil/deploy/runtime SIGIL_RESET=1 bash deploy/init.sh  # first install only
# easiest trusted cert on this host: Tailscale Let's Encrypt cert
SIGIL_RUNTIME=/opt/sigil/deploy/runtime bash deploy/issue-tailscale-cert.sh
SIGIL_EDGE_BIND=127.0.0.1 docker compose -f deploy/docker-compose.prod.yml -p sigil-prod up -d --wait
SIGIL_BASE=https://contabo-vps.tailf8e6be.ts.net:19443/gate bash deploy/smoke.sh
```

`SIGIL_EDGE_BIND` defaults to `127.0.0.1`. Set it to the Tailscale IP to serve
the Tailscale certificate; keep loopback-only if you use a local TLS terminator.

`SIGIL_RESET=1` deletes data, effects and keys. Never use it on an existing production
instance.

## Selected mode: tailnet-only

- No public DNS, Cloudflare tunnel or public WAF is enabled.
- The edge is bound to the Tailscale IP from `deploy/.env` (`SIGIL_EDGE_BIND`).
- Access is only through `https://contabo-vps.tailf8e6be.ts.net:19443/`.
- Never set `SIGIL_EDGE_BIND=0.0.0.0` unless you deliberately want public exposure.

## Network and TLS

- The only published port is `19443` (nginx TLS edge), bound to `SIGIL_EDGE_BIND`
  (default `127.0.0.1`). Gate, verify, anchor, KMS and context have no host ports and sit
  on an `internal: true` network.
- The edge routes `/gate/`, `/verify/`, `/anchor/`, `/ctx/` and applies HSTS and security
  headers; `/gate/` is rate-limited to 30 r/s with burst 60.
- `init.sh` creates a **self-signed bootstrap certificate** only as fallback.
  `issue-tailscale-cert.sh` installs a public Let's Encrypt certificate for
  `contabo-vps.tailf8e6be.ts.net` (Tailscale), valid 90 days; renew monthly and restart
  `sigil-prod-edge-1`.
- For non-Tailnet/public access, replace `runtime/tls/fullchain.pem` and `privkey.pem`
  with a certificate for your DNS name and bind the edge accordingly.
- If remote access is required, keep the edge behind WireGuard/SSH or a trusted TLS
  terminator with a real certificate.

## Secrets and keys

- Control, approver and KMS tokens are Docker secrets under `/run/secrets`.
- Private keys are bind-mounted read-only from `runtime/keys/kms`, mode `0600`, owner
  `65534:65534`. They are never baked into the image.
- The TLS private key is `runtime/tls/privkey.pem` (`0600`, owner `65534`).
- Back up `runtime/keys` separately, encrypted and offline. The regular backup script
  deliberately excludes private keys.
Current encrypted key backup (24.10.2026): Linux3 data disk
`/media/renato/sanjin/SIGIL/` (archive + SHA-256 + manifest). The GPG private key is in
`/home/renato/.gnupg-sigil` on the Linux3 root disk, not on the data disk. This is
encrypted-at-rest and on a separate machine/disk, but not air-gapped; keep a USB/offsite
copy when available.

- When the USB/offline disk is mounted:

```bash
SIGIL_RUNTIME=/opt/sigil/deploy/runtime \
  bash deploy/backup-keys-usb.sh /media/USB
```

  Copy the resulting `.tar.gz.gpg` and `.sha256` to the house/offline copy. The passphrase
  is not stored; keep it offline. Restore only in a disaster, then restart the stack:

```bash
SIGIL_RESTORE_KEYS_FORCE=1 \
  SIGIL_RUNTIME=/opt/sigil/deploy/runtime \
  bash deploy/restore-keys-usb.sh /media/USB/sigil-keys-*.tar.gz.gpg
```

- Rotate with `sigil-rotate`; publish the new public key before switching `SIGIL_KEY_ID`,
  then restart the signing service. Old public keys stay available for old receipts.

## Durability and recovery

```bash
bash deploy/backup.sh /secure/backups
```

The archive contains a consistent SQLite backup, anchor log, context store and public
keys, plus a SHA-256 file. Test restore into a separate runtime before relying on it:

```bash
bash deploy/restore.sh backups/<file>.tar.gz /tmp/sigil-restore-test
```

The restore script refuses to overwrite an existing database unless `SIGIL_RESTORE_FORCE=1`;
it verifies SQLite integrity and the full receipt chain inside the pinned image.

Backups keep the last 14 archives (`SIGIL_BACKUP_KEEP`). `sigil-rehearsal.timer` runs the
backup + restore rehearsal weekly and verifies the chain; failure leaves a failed systemd
unit and the rehearsal temp directory is removed by trap.

## Read-only standby

A verified read-only replica runs on Oracle (`deploy/STANDBY.md`): it pulls receipts,
re-verifies hashes and signatures every 5 minutes, and keeps the last valid chain locally.
It is not write HA and does not fail over automatically.

## Current production state

- Chain ID: `sigil-prod-1` (clean chain; old test data archived in `backups/pre-prod-*.tar.gz`).
- Control/approver/KMS tokens rotated on 24.10.2026; clients must use the new
  `runtime/keys/control_token` / `approver_token`.
- Current encrypted key backup: `sigil-keys-prod-20261024T181449Z.tar.gz.gpg` on
  Linux3 (`/media/renato/sanjin/SIGIL`), SHA-256 `1975cfb1…`.
- Read-only standby on Oracle re-synced and valid.

## Recovery material

- Encrypted recovery key bundle (contains GPG private key + README):
  `sigil-recovery-key-20261024T182240Z.tar.gz.gpg`
  - location: Podrum, `C:\Users\Korisnik\Downloads`
  - SHA-256: `dbb773b85d59776b475ae45919cebeee8c3f56d058f6d376df04a467d1ba0181`
  - passphrase is **not stored on this server**; keep it separately.
- Encrypted data backup:
  `sigil-data-prod-20261024T182305Z.tar.gz.gpg`
  - location: Podrum, `C:\Users\Korisnik\Downloads`
  - SHA-256: `eb90238d136fdd6f4211f702c5819719f8cbb44137cd82bed6f191a6a0c87a9e`
  - same recovery passphrase.
- Alert monitor: `sigil-alert.timer` checks health/chain/metrics every 15 minutes and emails
  `renato.schuster@gmail.com` once per incident and once on recovery (no periodic reminders).

## Operations

- Container healthchecks: every service has one; use `docker compose ... ps`.
- Logs: `docker logs <container>`; json-file rotation is capped at 3 x 10 MB.
- Upgrades: build/pin a new immutable image, back up, then `docker compose ... up -d --wait`
  and run `deploy/smoke.sh`. Roll back to the previous image tag/digest.
- Monitor `https://.../gate/health` (`lease`, chain id), `/gate/chain/verify` and `/gate/metrics`
  (`sigil_chain_receipts`, `sigil_requests_total`, `sigil_errors_total`, `sigil_lease_valid`);
  alert on failures or a flat/stuck receipt count.
- Resource limits are set per service; adjust only after measuring.

## Go-live gate

- [x] Real TLS certificate (Tailscale Let's Encrypt, tailnet-only)
- [x] Public DNS/CA **not required** — tailnet-only selected
- [ ] Offline encrypted backup of `runtime/keys`
- [x] Restore rehearsal succeeded
- [ ] Image pinned by digest and vulnerability-scanned
- [ ] Monitoring/alerting on health, chain verification and disk
- [x] Key rotation rehearsal
- [x] Production chain reset + token rotation
- [ ] Incident/rollback owner assigned

## Known gaps (do not claim these are done)

- No full Raft or cross-host write consensus; quorum lease certificates are present.
- No cloud KMS/HSM adapter tested with real AWS/GCP/Azure credentials.
- Real Zed editor E2E remains untested (no `zed` binary / `DISPLAY` in this lab).
- The edge rate-limits `/gate/` only; there is no WAF or per-token quota.
- No external RFC3161 TSA in this profile (`SIGIL_TSA_ENABLE=0`).
- TLS is real Let's Encrypt for `contabo-vps.tailf8e6be.ts.net`, reachable on the tailnet only.
