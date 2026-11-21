#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the opt-in, iOS-only SMX socket I/O correlation trace patch.

The check uses a miniature tree containing only the pinned Wine files and the
BCD source forks that the IPA build actually compiles. It proves that the patch
is idempotent, changes no source text outside its marked blocks, does not
change the Wine server protocol, keeps runtime insertions under WINE_IOS, and
wires the diagnostic into the IPA workflow before the affected builds.

Set WINE_SRC when the product archive's wine/ submodule is not populated.
"""
from pathlib import Path
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
WINE = Path(os.environ.get("WINE_SRC", ROOT / "wine")).resolve()
PATCH = ROOT / "tools/patch-wine-smx-socket-io-trace.py"
WORKFLOW = ROOT / ".github/workflows/build-ipa.yml"

WINE_FILES = (
    "server/async.c",
    "server/thread.c",
    "server/sock.c",
    "server/fd.c",
    "server/file.h",
    "dlls/ntdll/unix/file.c",
    "dlls/ntdll/unix/socket.c",
    "dlls/ntdll/unix/unix_private.h",
)
BCD_FILES = (
    "build/wineserver/fd_ios.c",
    "build/ntdll-unix/server_ios.c",
)
HELPERS = (
    "wine/server/smx_socket_io_trace.h",
    "wine/dlls/ntdll/unix/smx_socket_io_trace.h",
)
BEGIN = "/* smx-socket-io-trace:begin "
END = "/* smx-socket-io-trace:end "


def fail(message):
    print(f"FAIL: {message}")
    raise SystemExit(1)


def ok(message):
    print(f"ok: {message}")


def read(path):
    return path.read_text(encoding="utf-8")


def strip_marked(text):
    """Remove marked diagnostic blocks, preserving all other source text."""
    out = []
    pos = 0
    while True:
        begin = text.find(BEGIN, pos)
        if begin < 0:
            out.append(text[pos:])
            break
        out.append(text[pos:begin])
        marker_end = text.find("*/", begin)
        if marker_end < 0:
            fail("unterminated diagnostic begin marker")
        name = text[begin + len(BEGIN):marker_end].strip()
        end_marker = END + name + " */"
        end = text.find(end_marker, marker_end + 2)
        if end < 0:
            fail(f"missing diagnostic end marker for {name}")
        after = end + len(end_marker)
        # The patch adds one separator newline after each marked block. It is
        # part of the diagnostic insertion, not an unmarked source change.
        if text.startswith("\n", after):
            after += 1
        pos = after
    return "".join(out)


def copy_tree(tmp):
    tree = tmp / "tree"
    for rel in WINE_FILES + ("include/wine/server_protocol.h",):
        src = WINE / rel
        if not src.is_file():
            fail(f"missing pinned Wine source: {src}")
        dst = tree / "wine" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    for rel in BCD_FILES:
        src = ROOT / rel
        if not src.is_file():
            fail(f"missing BCD source: {src}")
        dst = tree / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return tree


def run_patch(tree, expect_ok=True, argument=None):
    result = subprocess.run(
        [sys.executable, str(PATCH), str(argument if argument is not None else tree)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if expect_ok and result.returncode != 0:
        fail(f"patch failed ({result.returncode}):\n{result.stdout}")
    return result


def assert_contains(path, needles, label):
    text = read(path)
    for needle in needles:
        if needle not in text:
            fail(f"{label} is missing {needle!r} in {path}")


def main():
    if not PATCH.is_file():
        fail(f"missing patch script: {PATCH}")
    if not WINE.is_dir():
        fail(f"missing pinned Wine checkout: {WINE}")

    with tempfile.TemporaryDirectory(prefix="smx-socket-trace-") as td:
        tree = copy_tree(Path(td))
        protocol_before = hashlib.sha256(
            (tree / "wine/include/wine/server_protocol.h").read_bytes()
        ).hexdigest()
        originals = {
            "wine/" + rel: read(tree / "wine" / rel) for rel in WINE_FILES
        }
        originals.update({rel: read(tree / rel) for rel in BCD_FILES})

        run_patch(tree)
        ok("patch applies to the pinned Wine/BCD source set")

        shorthand_tree = copy_tree(Path(td) / "shorthand")
        run_patch(shorthand_tree, argument=shorthand_tree / "wine")
        ok("patch accepts the workflow's Wine-root shorthand")

        for rel, original in originals.items():
            patched = read(tree / rel)
            if strip_marked(patched) != strip_marked(original):
                fail(f"patch changed source outside marked blocks: {rel}")
        ok("all source edits are confined to marked diagnostic blocks")

        protocol_after = hashlib.sha256(
            (tree / "wine/include/wine/server_protocol.h").read_bytes()
        ).hexdigest()
        if protocol_before != protocol_after:
            fail("the Wine server protocol changed")
        ok("the Wine server protocol is unchanged")

        before_second = {
            p: p.read_bytes() for p in tree.rglob("*") if p.is_file()
        }
        second = run_patch(tree)
        if "already applied" not in second.stdout.lower():
            fail(f"second patch run was not recognized as idempotent:\n{second.stdout}")
        after_second = {
            p: p.read_bytes() for p in tree.rglob("*") if p.is_file()
        }
        if before_second != after_second:
            fail("second patch run changed the tree")
        ok("the patch is idempotent")

        required = {
            "wine/server/async.c": (
                '"server-complete"', "async_get_smx_io_op",
                "async_get_smx_io_tid", "async_get_smx_io_iosb",
                "async_get_smx_io_tid( &async->obj ), current->id",
            ),
            "wine/server/thread.c": (
                '"apc-requeue"', '"apc-destroy"', '"apc-result-returned"',
                "apc->smx_dropped", "apc->result.type == APC_ASYNC_IO",
                "async_get_smx_io_tid( apc->owner )", "current->id",
            ),
            "wine/server/sock.c": (
                '"RECV"', '"server-request"',
                "async_get_smx_io_async_tid( async ), current->id",
            ),
            "wine/server/fd.c": (
                '"AFD_POLL"', '"server-request"',
                "async_get_smx_io_async_tid( async ), current->id",
            ),
            "build/wineserver/fd_ios.c": (
                '"AFD_POLL"', '"server-request"',
                "async_get_smx_io_async_tid( async ), current->id",
            ),
            "wine/dlls/ntdll/unix/file.c": (
                '"AFD_POLL"', '"guest-request"', '"guest-result"',
                "if (!smx_socket_io_get_iosb( io, &guest_status, &guest_info ))",
                "unsigned int guest_status = STATUS_UNSUCCESSFUL;",
                "smx_socket_io_win32_error( guest_status )",
                "GetCurrentThreadId(), GetCurrentThreadId()",
            ),
            "wine/dlls/ntdll/unix/socket.c": (
                '"RECV"', '"guest-request"', '"guest-result"',
                "if (!smx_socket_io_get_iosb( io, &guest_status, &guest_info ))",
                "unsigned int guest_status = STATUS_UNSUCCESSFUL;",
                "smx_socket_io_win32_error( guest_status )",
                "GetCurrentThreadId(), GetCurrentThreadId()",
            ),
            "wine/dlls/ntdll/unix/unix_private.h": (
                "static inline BOOL smx_socket_io_get_iosb",
                "return FALSE;", "return TRUE;",
                "ReadAcquire( &io32->Status )",
                "ReadAcquire( &io->Status )", '"guest-iosb-write"',
                "GetCurrentThreadId(), GetCurrentThreadId()",
            ),
        }
        for rel, needles in required.items():
            assert_contains(tree / rel, needles, "trace contract")
        ok("required operation kinds, events, owner/executor IDs, and IOSB reads are present")

        for rel in ("wine/dlls/ntdll/unix/file.c", "wine/dlls/ntdll/unix/socket.c"):
            text = read(tree / rel)
            wait_index = text.find("status = wait_async(")
            result_index = text.find('smx_socket_io_trace( "guest-result"')
            if wait_index < 0 or result_index < 0 or wait_index >= result_index:
                fail(f"the guest result is not read after wait_async in {rel}")
            if "guest_status = STATUS_PENDING;" in text:
                fail(f"a default pending status can masquerade as an observed guest IOSB in {rel}")
        ok("guest results are observed after the wait rather than inferred from a default")

        unix_private = read(tree / "wine/dlls/ntdll/unix/unix_private.h")
        write_index = unix_private.rfind("WriteRelease( &io->Status, status );")
        trace_index = unix_private.find('smx_socket_io_trace( "guest-iosb-write"')
        if write_index < 0 or trace_index < 0 or write_index >= trace_index:
            fail("the guest IOSB write event is not logged after the actual release write")
        ok("the guest IOSB write event follows the real release write")

        source_paths = ["wine/" + rel for rel in WINE_FILES] + list(BCD_FILES)
        for rel in source_paths:
            text = read(tree / rel)
            for block in re.findall(
                r"/\* smx-socket-io-trace:begin .*?\*/(.*?)/\* smx-socket-io-trace:end .*?\*/",
                text,
                flags=re.S,
            ):
                if "#ifdef WINE_IOS" not in block:
                    fail(f"runtime diagnostic block is not guarded by WINE_IOS in {rel}")
        for rel in HELPERS:
            path = tree / rel
            if not path.is_file():
                fail(f"missing generated trace helper: {path}")
            text = read(path)
            if "#ifdef WINE_IOS" not in text or "#endif" not in text:
                fail(f"trace helper is not fully iOS-guarded: {rel}")
            if "owner_tid=%04x" not in text or "executor_tid=%04x" not in text:
                fail(f"trace helper does not distinguish owner and executor threads in {rel}")
            if "if (status == 0x00000103) return 997;" not in text:
                fail(f"trace helper does not map STATUS_PENDING to Win32 error 997 in {rel}")
            if "if (status == 0x00000101) return 739;" not in text:
                fail(f"trace helper does not map STATUS_ALERTED to Win32 error 739 in {rel}")
            if "int saved_errno = errno;" not in text or "errno = saved_errno;" not in text:
                fail(f"trace helper does not preserve errno in {rel}")
            if "static int enabled = -1;" in text:
                fail(f"trace helper caches the disabled state before the bridge exports the switch in {rel}")
            if "static int enabled = 0;" not in text or "return 1;" not in text:
                fail(f"trace helper does not enable later when the bridge exports the switch in {rel}")
        ok("every runtime trace block is guarded by WINE_IOS")
        ok("the trace helper preserves errno and permits late enablement")

        assert_contains(
            tree / "build/ntdll-unix/server_ios.c",
            ("ios_set_async_iosb", "set_async_iosb( iosb, status, info )"),
            "actual iOS ntdll APC path",
        )
        ok("the actual iOS ntdll APC path reaches the instrumented IOSB writer")

    workflow = read(WORKFLOW)
    patch_command = "python3 tools/patch-wine-smx-socket-io-trace.py wine"
    check_command = "python3 tests/host/check-smx-socket-io-trace.py"
    patch_step = workflow.find(patch_command)
    check_step = workflow.find(check_command)
    ntdll_build = workflow.find("Build ntdll-unix")
    base_wineserver_build = workflow.find("Build base libwineserver.a from wine/server sources")
    wineserver_build = workflow.find("Build wineserver")
    if patch_step < 0 or check_step < 0:
        fail("the IPA workflow does not apply and check the SMX socket trace patch")
    if ntdll_build < 0 or base_wineserver_build < 0 or wineserver_build < 0:
        fail("the IPA workflow no longer has the expected affected build steps")
    if patch_step >= ntdll_build or patch_step >= base_wineserver_build or patch_step >= wineserver_build:
        fail("the IPA workflow applies the SMX trace after an affected build")
    ok("the IPA workflow applies and checks the patch before the affected builds")

    print("PASS: SMX socket I/O trace patch is opt-in, iOS-only, idempotent, and protocol-neutral")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
