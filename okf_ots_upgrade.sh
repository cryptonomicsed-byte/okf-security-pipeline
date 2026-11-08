#!/bin/bash
# Upgrade every OpenTimestamps proof under the receipt store.
#
# ots exits 123 when a proof is still only a PendingAttestation (the calendar
# commitment has not been included in a Bitcoin block yet). That is the normal
# state for the first hours, not a failure — so 123 is treated as success and
# anything else exits with its own code so systemd surfaces real errors.
set -uo pipefail

mapfile -d '' files < <(find /opt/ares/security_receipts -name '*.ots' -print0 2>/dev/null)
if [ ${#files[@]} -eq 0 ]; then
    echo "no .ots proofs yet"
    exit 0
fi

echo "upgrading ${#files[@]} proof(s)"
out=$(/opt/ares/venv/bin/ots upgrade "${files[@]}" 2>&1)
rc=$?
echo "$out"

# Koodu BTC-Time: turn any newly upgraded Bitcoin height into ecosystem time
# vocabulary and write <receipt>.time.json. Pending proofs are skipped.
echo "--- btc-time sidecars ---"
/usr/bin/python3 /opt/ares/koodu_time.py --all 2>&1 | tail -25 || true

# Emit signed time-attestations for every proof that verified against a block
# header (sidecars are a cache; the attestation is the artifact).
# `|| true` here hid a KeyError for days: the timer logged a traceback and systemd
# still reported "Finished". A crashed step must fail the unit.
attest_out=$(/opt/ares/venv/bin/python3 /opt/ares/okf_time_attest.py --all 2>&1)
attest_rc=$?
echo "$attest_out" | tail -10
if [ "$attest_rc" -ne 0 ]; then
    echo "attestation step failed with rc=$attest_rc"
    exit "$attest_rc"
fi

if [ "$rc" -eq 0 ]; then
    echo "all proofs upgraded (Bitcoin attestation)"
    exit 0
fi
if echo "$out" | grep -qiE "pending confirmation|timestamp not complete|pending attestation"; then
    echo "still pending Bitcoin confirmation — retrying next hour (rc=$rc)"
    exit 0
fi
echo "ots upgrade failed with rc=$rc"
exit "$rc"