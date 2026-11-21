#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the host-side SMX socket I/O trace correlation analyzer."""
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ANALYZER = ROOT / "tools/analyze-smx-socket-io-trace.py"

STATUS_PENDING = "0x00000103"
STATUS_ALERTED = "0x00000101"


def run(log):
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".log") as f:
        f.write(log)
        f.flush()
        return subprocess.run(
            [sys.executable, str(ANALYZER), f.name],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )


def fail(message):
    print(f"FAIL: {message}")
    raise SystemExit(1)


def ok(message):
    print(f"ok: {message}")


def line(event, op="RECV", owner="0000", executor="0068", iosb="0xabc",
         status=STATUS_PENDING, info="0", win32="0", wait_status="0x00000000",
         detail="recv"):
    return (
        f"[smx-io] event={event} op={op} owner_tid={owner} executor_tid={executor} "
        f"iosb={iosb} status={status} info={info} win32={win32} "
        f"wait_status={wait_status} detail={detail}\n"
    )


def request_chain(*, owner="00a0", executor="0068", iosb="0xabc", info="13"):
    return (
        line("guest-request", owner="0000", executor=executor, iosb=iosb,
             status=STATUS_PENDING, detail="recv") +
        line("server-request", owner=owner, executor="0000", iosb=iosb,
             status=STATUS_PENDING, detail="recv") +
        line("server-complete", owner=owner, executor="0000", iosb=iosb,
             status=STATUS_ALERTED, info=info, win32="739", detail="apc") +
        line("apc-requeue", owner=owner, executor="0000", iosb=iosb,
             status=STATUS_ALERTED, detail="dropped") +
        line("apc-destroy", owner=owner, executor="0000", iosb=iosb,
             status=STATUS_ALERTED, detail="dropped") +
        line("guest-result", owner="0000", executor=executor, iosb=iosb,
             status=STATUS_PENDING, info=info, win32="997",
             wait_status=STATUS_PENDING, detail="recv")
    )


def require_not_correlated(name, log):
    result = run(log)
    if result.returncode == 0 or "NOT CORRELATED" not in result.stdout:
        fail(f"{name} was claimed as correlated:\n{result.stdout}")
    ok(f"{name} is not claimed as correlated")


def main():
    if not ANALYZER.is_file():
        fail(f"missing analyzer: {ANALYZER}")

    correlated = request_chain() + \
        "System.Net.Sockets.SocketException: Overlapped I/O pending.\n"
    result = run(correlated)
    if result.returncode != 0:
        fail(f"correlated trace was rejected ({result.returncode}):\n{result.stdout}")
    for needle in (
        "CORRELATED op=RECV iosb=0xabc",
        "guest_owner_tid=0000",
        "guest_executor_tid=0068",
        "server_owner_tid=00a0",
        "server_executor_tid=0000",
        "apc_executor_tid=0000",
        "completion_status=0x00000101",
        "drop_status=0x00000101",
        "guest_status=0x00000103",
        "information=13",
        "final_win32=997",
    ):
        if needle not in result.stdout:
            fail(f"correlated output is missing {needle!r}:\n{result.stdout}")
    ok("the complete dropped-APC chain is correlated with positive guest pending state")

    without_server_request = "\n".join(
        record for record in request_chain().splitlines()
        if "event=server-request" not in record
    ) + "\n"
    result = run(without_server_request)
    if result.returncode != 0 or "CORRELATED" not in result.stdout:
        fail(f"a complete chain without a redundant server-request was rejected:\n{result.stdout}")
    ok("the server-request event is not required when the complete chain is present")

    ambiguous = correlated + request_chain(
        owner="0069", executor="0069", iosb="0xdef", info="7"
    )
    result = run(ambiguous)
    if result.returncode == 0 or "AMBIGUOUS" not in result.stdout:
        fail(f"multiple complete candidates were not rejected as ambiguous:\n{result.stdout}")
    ok("multiple complete request candidates are rejected as ambiguous")

    require_not_correlated(
        "a request without a server completion",
        line("guest-request") + line("server-request") +
        line("apc-requeue", status=STATUS_ALERTED, detail="dropped") +
        line("apc-destroy", status=STATUS_ALERTED, detail="dropped") +
        line("guest-result", status=STATUS_PENDING, win32="997"),
    )
    require_not_correlated(
        "a request without a dropped APC requeue",
        line("guest-request") + line("server-request") +
        line("server-complete", status=STATUS_ALERTED, info="13", win32="739", detail="apc") +
        line("apc-destroy", status=STATUS_ALERTED, detail="dropped") +
        line("guest-result", status=STATUS_PENDING, info="13", win32="997"),
    )
    require_not_correlated(
        "a request without dropped APC destruction",
        line("guest-request") + line("server-request") +
        line("server-complete", status=STATUS_ALERTED, info="13", win32="739", detail="apc") +
        line("apc-requeue", status=STATUS_ALERTED, detail="dropped") +
        line("guest-result", status=STATUS_PENDING, info="13", win32="997"),
    )
    require_not_correlated(
        "a request without a later guest result",
        line("guest-request") + line("server-request") +
        line("server-complete", status=STATUS_ALERTED, info="13", win32="739", detail="apc") +
        line("apc-requeue", status=STATUS_ALERTED, detail="dropped") +
        line("apc-destroy", status=STATUS_ALERTED, detail="dropped"),
    )
    require_not_correlated(
        "a guest result whose actual IOSB is not pending",
        line("guest-request") + line("server-request") +
        line("server-complete", status=STATUS_ALERTED, info="13", win32="739", detail="apc") +
        line("apc-requeue", status=STATUS_ALERTED, detail="dropped") +
        line("apc-destroy", status=STATUS_ALERTED, detail="dropped") +
        line("guest-result", status="0x00000000", info="13", win32="0",
             wait_status="0x00000000"),
    )
    require_not_correlated(
        "a guest result executed by a different thread",
        line("guest-request", owner="0000", executor="0068") +
        line("server-request", owner="00a0") +
        line("server-complete", owner="00a0", status=STATUS_ALERTED, info="13", win32="739", detail="apc") +
        line("apc-requeue", owner="00a0", status=STATUS_ALERTED, detail="dropped") +
        line("apc-destroy", owner="00a0", status=STATUS_ALERTED, detail="dropped") +
        line("guest-result", owner="0000", executor="0069", status=STATUS_PENDING,
             info="13", win32="997"),
    )

    require_not_correlated(
        "a server completion with the wrong status",
        line("guest-request") + line("server-request") +
        line("server-complete", status="0x00000000", info="13", win32="0", detail="apc") +
        line("apc-requeue", status=STATUS_ALERTED, detail="dropped") +
        line("apc-destroy", status=STATUS_ALERTED, detail="dropped") +
        line("guest-result", status=STATUS_PENDING, info="13", win32="997"),
    )

    require_not_correlated(
        "an APC destruction that does not correspond to its requeue",
        line("guest-request") + line("server-request") +
        line("server-complete", status=STATUS_ALERTED, info="13", win32="739", detail="apc") +
        line("apc-requeue", status=STATUS_ALERTED, info="0", detail="dropped") +
        line("apc-destroy", status=STATUS_ALERTED, info="13", detail="dropped") +
        line("guest-result", status=STATUS_PENDING, info="13", win32="997"),
    )

    duplicate_completion = (
        line("guest-request") + line("server-request") +
        line("server-complete", owner="00a0", status=STATUS_ALERTED,
             info="13", win32="739", detail="apc") +
        line("server-complete", owner="00a0", status=STATUS_ALERTED,
             info="14", win32="739", detail="apc") +
        line("apc-requeue", owner="00a0", status=STATUS_ALERTED, detail="dropped") +
        line("apc-destroy", owner="00a0", status=STATUS_ALERTED, detail="dropped") +
        line("guest-result", status=STATUS_PENDING, info="13", win32="997")
    )
    result = run(duplicate_completion)
    if result.returncode == 0 or "AMBIGUOUS" not in result.stdout:
        fail(f"duplicate matching completions were not rejected as ambiguous:\n{result.stdout}")
    ok("duplicate evidence in one request segment is rejected as ambiguous")

    reused_iosb = request_chain(iosb="0xabc", info="13")
    reused_iosb += line("guest-request", owner="0000", executor="0070", iosb="0xabc",
                        status=STATUS_PENDING, detail="recv")
    result = run(reused_iosb)
    if result.returncode != 0 or "CORRELATED" not in result.stdout:
        fail(f"a reused IOSB was not isolated into request segments:\n{result.stdout}")
    if "AMBIGUOUS" in result.stdout:
        fail(f"an incomplete reused-IOSB request was treated as ambiguous:\n{result.stdout}")
    ok("reused guest IOSBs are isolated at each guest request")

    out_of_order = (
        line("guest-request") + line("server-request") +
        line("apc-requeue", status=STATUS_ALERTED, detail="dropped") +
        line("guest-result", status=STATUS_PENDING, info="13", win32="997") +
        line("server-complete", status=STATUS_ALERTED, info="13", win32="739", detail="apc") +
        line("apc-destroy", status=STATUS_ALERTED, detail="dropped")
    )
    require_not_correlated("an out-of-order event chain", out_of_order)

    print("PASS: SMX socket I/O trace analyzer rejects ambiguous and incomplete correlations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
