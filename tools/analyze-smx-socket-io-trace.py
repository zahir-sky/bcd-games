#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Correlate the opt-in SMX socket I/O device trace.

The analyzer starts a new request segment at every guest request. A confirmed
candidate must contain one matching server request and completion, one dropped
STATUS_ALERTED APC requeue, one dropped APC destruction, and one later guest
result whose actual guest IO_STATUS_BLOCK still contains STATUS_PENDING.
Owner and executor thread IDs are kept separate and must agree across the
server/client boundary. More than one complete candidate is ambiguous.
"""
from pathlib import Path
import re
import sys

TRACE_RE = re.compile(
    r"\[smx-io\]\s+event=(?P<event>\S+)\s+op=(?P<op>\S+)\s+"
    r"owner_tid=(?P<owner_tid>[0-9a-fA-F]+)\s+"
    r"executor_tid=(?P<executor_tid>[0-9a-fA-F]+)\s+"
    r"iosb=(?P<iosb>0x[0-9a-fA-F]+)\s+"
    r"status=(?P<status>0x[0-9a-fA-F]+)\s+info=(?P<info>\d+)\s+"
    r"win32=(?P<win32>\d+)\s+wait_status=(?P<wait_status>0x[0-9a-fA-F]+)\s+"
    r"detail=(?P<detail>.*)$"
)
STATUS_PENDING = 0x00000103
STATUS_ALERTED = 0x00000101
ERROR_IO_PENDING = 997


def parse_records(text):
    records = []
    for raw in text.splitlines():
        match = TRACE_RE.search(raw)
        if not match:
            continue
        record = match.groupdict()
        record["owner_tid"] = int(record["owner_tid"], 16)
        record["executor_tid"] = int(record["executor_tid"], 16)
        record["iosb"] = record["iosb"].lower()
        record["status"] = int(record["status"], 16)
        record["info"] = int(record["info"])
        record["win32"] = int(record["win32"])
        record["wait_status"] = int(record["wait_status"], 16)
        records.append(record)
    return records


def request_segments(records):
    """Split at every guest request so a reused stack IOSB cannot join requests."""
    segments = []
    current = None
    for record in records:
        if record["event"] == "guest-request":
            current = [record]
            segments.append(current)
        elif current is not None:
            current.append(record)
    return segments


def matching(segment, event, op, iosb):
    return [
        (index, record)
        for index, record in enumerate(segment)
        if record["event"] == event
        and record["op"] == op
        and record["iosb"] == iosb
    ]


def candidate_from_segment(segment):
    request = segment[0]
    op = request["op"]
    iosb = request["iosb"]

    completions = [
        (index, record)
        for index, record in matching(segment, "server-complete", op, iosb)
        if record["status"] == STATUS_ALERTED and record["detail"] == "apc"
    ]
    guest_results = [
        (index, record)
        for index, record in matching(segment, "guest-result", op, iosb)
        if record["owner_tid"] == request["owner_tid"]
        and record["executor_tid"] == request["executor_tid"]
    ]

    counts = (len(completions), len(guest_results))
    if any(count > 1 for count in counts):
        return "ambiguous", {
            "op": op,
            "iosb": iosb,
            "guest_owner_tid": request["owner_tid"],
            "guest_executor_tid": request["executor_tid"],
            "events": [record["event"] for record in segment],
        }
    if not completions or not guest_results:
        return "incomplete", None

    completion_index, completion = completions[0]
    server_owner = completion["owner_tid"]
    requeues = [
        (index, record)
        for index, record in matching(segment, "apc-requeue", op, iosb)
        if record["status"] == STATUS_ALERTED
        and record["detail"] == "dropped"
        and record["owner_tid"] == server_owner
    ]
    destroys = [
        (index, record)
        for index, record in matching(segment, "apc-destroy", op, iosb)
        if record["status"] == STATUS_ALERTED
        and record["detail"] == "dropped"
        and record["owner_tid"] == server_owner
    ]
    if len(requeues) > 1 or len(destroys) > 1:
        return "ambiguous", {
            "op": op,
            "iosb": iosb,
            "guest_owner_tid": request["owner_tid"],
            "guest_executor_tid": request["executor_tid"],
            "events": [record["event"] for record in segment],
        }
    if not requeues or not destroys:
        return "incomplete", None

    requeue_index, requeue = requeues[0]
    destroy_index, destroy = destroys[0]
    result_index, result = guest_results[0]

    if not (
        completion_index < requeue_index < destroy_index < result_index
    ):
        return "incomplete", None
    if destroy["info"] != requeue["info"]:
        return "incomplete", None
    if result["status"] != STATUS_PENDING or result["win32"] != ERROR_IO_PENDING:
        return "incomplete", None

    information = completion["info"] or result["info"]
    candidate = {
        "op": op,
        "iosb": iosb,
        "guest_owner_tid": request["owner_tid"],
        "guest_executor_tid": request["executor_tid"],
        "server_owner_tid": completion["owner_tid"],
        "server_executor_tid": completion["executor_tid"],
        "apc_executor_tid": requeue["executor_tid"],
        "request_status": request["status"],
        "completion_status": completion["status"],
        "drop_status": requeue["status"],
        "guest_status": result["status"],
        "information": information,
        "final_win32": result["win32"],
        "wait_status": result["wait_status"],
        "events": [record["event"] for record in segment],
    }
    return "candidate", candidate


def find_candidates(segments):
    candidates = []
    ambiguous = []
    for segment in segments:
        kind, candidate = candidate_from_segment(segment)
        if kind == "candidate":
            candidates.append(candidate)
        elif kind == "ambiguous":
            ambiguous.append(candidate)
    return candidates, ambiguous


def format_candidate(candidate):
    return (
        f"CORRELATED op={candidate['op']} iosb={candidate['iosb']} "
        f"guest_owner_tid={candidate['guest_owner_tid']:04x} "
        f"guest_executor_tid={candidate['guest_executor_tid']:04x} "
        f"server_owner_tid={candidate['server_owner_tid']:04x} "
        f"server_executor_tid={candidate['server_executor_tid']:04x} "
        f"apc_executor_tid={candidate['apc_executor_tid']:04x} "
        f"request_status=0x{candidate['request_status']:08x} "
        f"completion_status=0x{candidate['completion_status']:08x} "
        f"drop_status=0x{candidate['drop_status']:08x} "
        f"guest_status=0x{candidate['guest_status']:08x} "
        f"information={candidate['information']} "
        f"final_win32={candidate['final_win32']} "
        f"wait_status=0x{candidate['wait_status']:08x} "
        f"events={','.join(candidate['events'])}"
    )


def main(argv):
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} LOG", file=sys.stderr)
        return 64
    path = Path(argv[1])
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        print(f"cannot read {path}: {error}", file=sys.stderr)
        return 66

    segments = request_segments(parse_records(text))
    candidates, ambiguous = find_candidates(segments)
    if len(candidates) == 1 and not ambiguous:
        print(format_candidate(candidates[0]))
        return 0
    if len(candidates) > 1 or ambiguous:
        count = len(candidates) + len(ambiguous)
        print(f"AMBIGUOUS: {count} matching request segments")
        for candidate in candidates:
            print(format_candidate(candidate))
        for candidate in ambiguous:
            print(
                f"AMBIGUOUS op={candidate['op']} iosb={candidate['iosb']} "
                f"guest_owner_tid={candidate['guest_owner_tid']:04x} "
                f"guest_executor_tid={candidate['guest_executor_tid']:04x} "
                f"events={','.join(candidate['events'])}"
            )
        return 2

    print(
        "NOT CORRELATED: no request segment has a server completion, dropped "
        "STATUS_ALERTED requeue and destruction, and a later guest result whose "
        "actual IOSB remains STATUS_PENDING"
    )
    for segment in segments:
        events = [record["event"] for record in segment]
        if any(record["event"] == "apc-requeue" for record in segment):
            request = segment[0]
            print(
                f"drop-only op={request['op']} iosb={request['iosb']} "
                f"guest_owner_tid={request['owner_tid']:04x} "
                f"guest_executor_tid={request['executor_tid']:04x} "
                f"events={','.join(events)}"
            )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
