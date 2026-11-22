#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Apply the opt-in iOS SMX socket I/O correlation trace.

This is a diagnostic patch only. Every runtime insertion is under WINE_IOS and
is inert unless MADEIRA_SMX_IO_TRACE=1 is exported before the traced request.
It does not change the Wine server protocol or product behavior.
"""
from pathlib import Path
import sys

MARKER = "smx-socket-io-trace"


def read(path):
    return path.read_text(encoding="utf-8")


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def insert_after(text, anchor, addition, name):
    begin = f"/* {MARKER}:begin {name} */"
    end = f"/* {MARKER}:end {name} */"
    if begin in text:
        return text
    count = text.count(anchor)
    if count != 1:
        raise RuntimeError(f"anchor for {name} occurs {count} times")
    return text.replace(anchor, anchor + begin + "\n" + addition + end + "\n", 1)


def insert_before(text, anchor, addition, name):
    begin = f"/* {MARKER}:begin {name} */"
    end = f"/* {MARKER}:end {name} */"
    if begin in text:
        return text
    count = text.count(anchor)
    if count != 1:
        raise RuntimeError(f"anchor for {name} occurs {count} times")
    return text.replace(anchor, begin + "\n" + addition + end + "\n" + anchor, 1)


def insert_after_in_function(text, func_signature, anchor, addition, name):
    count = text.count(func_signature)
    if count != 1:
        raise RuntimeError(f"function signature for {name} occurs {count} times")
    start = text.index(func_signature)
    end = text.find("\n}\n", start)
    if end < 0:
        raise RuntimeError(f"end of function for {name} not found")
    end += 3
    body = insert_after(text[start:end], anchor, addition, name)
    return text[:start] + body + text[end:]


SERVER_HELPER = r'''#ifndef __WINE_SERVER_SMX_SOCKET_IO_TRACE_H
#define __WINE_SERVER_SMX_SOCKET_IO_TRACE_H

/* Diagnostic-only SMX socket I/O trace. It is deliberately unavailable in
 * non-iOS builds and has no effect unless MADEIRA_SMX_IO_TRACE=1. */
#ifdef WINE_IOS
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define SMX_IOCTL_AFD_POLL 0x00012024u

static inline int smx_socket_io_trace_enabled( void )
{
    static int enabled = 0;
    const char *value;

    /* The in-app wineserver starts before WineProcessBridge.m exports the
     * per-launch env.* lines. Recheck while disabled, then cache only the
     * enabled state. */
    if (__atomic_load_n( &enabled, __ATOMIC_RELAXED )) return 1;
    value = getenv( "MADEIRA_SMX_IO_TRACE" );
    if (value && value[0] == '1' && !value[1])
    {
        __atomic_store_n( &enabled, 1, __ATOMIC_RELAXED );
        return 1;
    }
    return 0;
}

static inline unsigned int smx_socket_io_win32_error( unsigned int status )
{
    if (status == 0x00000103) return 997;
    if (status == 0x00000101) return 739;
    return 0;
}

static inline void smx_socket_io_trace( const char *event, const char *op,
                                        unsigned int owner_tid,
                                        unsigned int executor_tid,
                                        unsigned long long iosb,
                                        unsigned int status,
                                        unsigned long long info,
                                        unsigned int win32,
                                        unsigned int wait_status,
                                        const char *detail )
{
    int saved_errno = errno;

    if (!smx_socket_io_trace_enabled())
    {
        errno = saved_errno;
        return;
    }
    fprintf( stderr, "[smx-io] event=%s op=%s owner_tid=%04x executor_tid=%04x "
             "iosb=0x%llx status=0x%08x info=%llu win32=%u wait_status=0x%08x "
             "detail=%s\n", event, op, owner_tid, executor_tid, iosb, status,
             info, win32, wait_status, detail );
    fflush( stderr );
    errno = saved_errno;
}
#endif

#endif
'''

CLIENT_HELPER = r'''#ifndef __WINE_NTDLL_UNIX_SMX_SOCKET_IO_TRACE_H
#define __WINE_NTDLL_UNIX_SMX_SOCKET_IO_TRACE_H

/* Diagnostic-only SMX socket I/O trace. It is deliberately unavailable in
 * non-iOS builds and has no effect unless MADEIRA_SMX_IO_TRACE=1. */
#ifdef WINE_IOS
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define SMX_IOCTL_AFD_POLL 0x00012024u

static inline int smx_socket_io_trace_enabled( void )
{
    static int enabled = 0;
    const char *value;

    /* The in-app wineserver starts before WineProcessBridge.m exports the
     * per-launch env.* lines. Recheck while disabled, then cache only the
     * enabled state. */
    if (__atomic_load_n( &enabled, __ATOMIC_RELAXED )) return 1;
    value = getenv( "MADEIRA_SMX_IO_TRACE" );
    if (value && value[0] == '1' && !value[1])
    {
        __atomic_store_n( &enabled, 1, __ATOMIC_RELAXED );
        return 1;
    }
    return 0;
}

static inline unsigned int smx_socket_io_win32_error( unsigned int status )
{
    if (status == 0x00000103) return 997;
    if (status == 0x00000101) return 739;
    return 0;
}

static inline void smx_socket_io_trace( const char *event, const char *op,
                                        unsigned int owner_tid,
                                        unsigned int executor_tid,
                                        unsigned long long iosb,
                                        unsigned int status,
                                        unsigned long long info,
                                        unsigned int win32,
                                        unsigned int wait_status,
                                        const char *detail )
{
    int saved_errno = errno;

    if (!smx_socket_io_trace_enabled())
    {
        errno = saved_errno;
        return;
    }
    fprintf( stderr, "[smx-io] event=%s op=%s owner_tid=%04x executor_tid=%04x "
             "iosb=0x%llx status=0x%08x info=%llu win32=%u wait_status=0x%08x "
             "detail=%s\n", event, op, owner_tid, executor_tid, iosb, status,
             info, win32, wait_status, detail );
    fflush( stderr );
    errno = saved_errno;
}
#endif

#endif
'''


def patch_server_file_h(path):
    text = read(path)
    text = insert_after(
        text,
        "extern void async_terminate( struct async *async, unsigned int status );\n",
        "#ifdef WINE_IOS\n"
        "extern void async_set_smx_io_op( struct async *async, const char *op );\n"
        "extern const char *async_get_smx_io_op( struct object *obj );\n"
        "extern unsigned int async_get_smx_io_tid( struct object *obj );\n"
        "extern client_ptr_t async_get_smx_io_iosb( struct object *obj );\n"
        "extern unsigned int async_get_smx_io_async_tid( struct async *async );\n"
        "extern client_ptr_t async_get_smx_io_async_iosb( struct async *async );\n"
        "#endif\n",
        "file-h-smx-accessors",
    )
    write(path, text)


def patch_server_async(path):
    text = read(path)
    text = insert_after(
        text,
        '#include "file.h"\n',
        "#ifdef WINE_IOS\n#include \"smx_socket_io_trace.h\"\n#endif\n",
        "async-trace-include",
    )
    text = insert_after(
        text,
        "    unsigned int         is_system :1;    /* background system operation not affecting userspace visible state. */\n",
        "#ifdef WINE_IOS\n"
        "    const char          *smx_io_op;      /* diagnostic operation kind: RECV or AFD_POLL */\n"
        "#endif\n",
        "async-smx-op-field",
    )
    text = insert_after(
        text,
        "    async->is_system     = 0;\n",
        "#ifdef WINE_IOS\n"
        "    async->smx_io_op     = NULL;\n"
        "#endif\n",
        "async-smx-op-init",
    )
    accessors = r'''#ifdef WINE_IOS
void async_set_smx_io_op( struct async *async, const char *op )
{
    if (async) async->smx_io_op = op;
}

const char *async_get_smx_io_op( struct object *obj )
{
    struct async *async = (struct async *)obj;

    return obj && obj->ops == &async_ops ? async->smx_io_op : NULL;
}

unsigned int async_get_smx_io_tid( struct object *obj )
{
    struct async *async = (struct async *)obj;

    return obj && obj->ops == &async_ops && async->thread ? async->thread->id : 0;
}

client_ptr_t async_get_smx_io_iosb( struct object *obj )
{
    struct async *async = (struct async *)obj;

    return obj && obj->ops == &async_ops ? async->data.iosb : 0;
}

unsigned int async_get_smx_io_async_tid( struct async *async )
{
    return async && async->thread ? async->thread->id : 0;
}

client_ptr_t async_get_smx_io_async_iosb( struct async *async )
{
    return async ? async->data.iosb : 0;
}
#endif

'''
    text = insert_before(
        text,
        "static inline void async_reselect( struct async *async )\n",
        accessors,
        "async-smx-accessors",
    )
    text = insert_after(
        text,
        "    if (status == STATUS_ALERTED)\n        async->alerted = 1;\n",
        "#ifdef WINE_IOS\n"
        "    {\n"
        "        const char *op = async_get_smx_io_op( &async->obj );\n"
        "        if (op)\n"
        "            smx_socket_io_trace( \"server-complete\", op,\n"
        "                                 async_get_smx_io_tid( &async->obj ), current->id,\n"
        "                                 async_get_smx_io_iosb( &async->obj ), status,\n"
        "                                 iosb ? iosb->result : 0,\n"
        "                                 smx_socket_io_win32_error( status ), 0,\n"
        "                                 async->direct_result ? \"direct\" : \"apc\" );\n"
        "    }\n"
        "#endif\n",
        "async-server-complete",
    )
    write(path, text)


def patch_server_thread(path):
    text = read(path)
    text = insert_after(
        text,
        '#include "file.h"\n',
        "#ifdef WINE_IOS\n#include \"smx_socket_io_trace.h\"\n#endif\n",
        "thread-trace-include",
    )
    text = insert_after(
        text,
        "    int                 executed; /* has it been executed by the client? */\n",
        "#ifdef WINE_IOS\n"
        "    int                 smx_dropped; /* completion APC was rejected before it was queued */\n"
        "#endif\n",
        "thread-apc-smx-dropped-field",
    )
    text = insert_after(
        text,
        "        apc->executed    = 0;\n",
        "#ifdef WINE_IOS\n"
        "        apc->smx_dropped = 0;\n"
        "#endif\n",
        "thread-apc-smx-dropped-init",
    )
    text = insert_after(
        text,
        "    if (apc->owner)\n    {\n",
        "#ifdef WINE_IOS\n"
        "        if (apc->smx_dropped && apc->call.type == APC_ASYNC_IO)\n"
        "        {\n"
        "            const char *op = async_get_smx_io_op( apc->owner );\n"
        "            smx_socket_io_trace( \"apc-destroy\", op ? op : \"ASYNC_IO\",\n"
        "                                 async_get_smx_io_tid( apc->owner ), current->id,\n"
        "                                 async_get_smx_io_iosb( apc->owner ),\n"
        "                                 apc->call.async_io.status,\n"
        "                                 apc->call.async_io.result,\n"
        "                                 smx_socket_io_win32_error( apc->call.async_io.status ),\n"
        "                                 0, \"dropped\" );\n"
        "        }\n"
        "#endif\n",
        "thread-apc-destroy-dropped",
    )
    text = insert_after(
        text,
        "    count++;\n    if (count <= 16 || !(count & 1023))\n",
        "#ifdef WINE_IOS\n"
        "    {\n"
        "        const char *op = async_get_smx_io_op( apc->owner );\n"
        "        smx_socket_io_trace( \"apc-requeue\", op ? op : \"ASYNC_IO\",\n"
        "                             async_get_smx_io_tid( apc->owner ),\n"
        "                             target ? target->id : 0,\n"
        "                             async_get_smx_io_iosb( apc->owner ),\n"
        "                             apc->call.async_io.status,\n"
        "                             apc->call.async_io.result,\n"
        "                             smx_socket_io_win32_error( apc->call.async_io.status ),\n"
        "                             0, target ? \"requeued\" : \"dropped\" );\n"
        "    }\n"
        "#endif\n",
        "thread-apc-requeue-event",
    )
    text = insert_after(
        text,
        "                struct thread *target = ios_apc_requeue_target( thread, apc );\n                if (!target) return 0;\n",
        "#ifdef WINE_IOS\n"
        "                apc->smx_dropped = 1;\n"
        "#endif\n",
        "thread-apc-mark-dropped",
    )
    text = insert_after(
        text,
        "        apc->result = *result;\n        apc->executed = 1;\n",
        "#ifdef WINE_IOS\n"
        "        if (apc->result.type == APC_ASYNC_IO)\n"
        "        {\n"
        "            const char *op = async_get_smx_io_op( apc->owner );\n"
        "            smx_socket_io_trace( \"apc-result-returned\", op ? op : \"ASYNC_IO\",\n"
        "                                 async_get_smx_io_tid( apc->owner ), current->id,\n"
        "                                 async_get_smx_io_iosb( apc->owner ),\n"
        "                                 apc->result.async_io.status,\n"
        "                                 apc->result.async_io.total,\n"
        "                                 smx_socket_io_win32_error( apc->result.async_io.status ),\n"
        "                                 0, \"returned\" );\n"
        "        }\n"
        "#endif\n",
        "thread-apc-returned-event",
    )
    write(path, text)


def patch_server_sock(path):
    text = read(path)
    text = insert_after(
        text,
        '#include "file.h"\n',
        "#ifdef WINE_IOS\n#include \"smx_socket_io_trace.h\"\n#endif\n",
        "sock-trace-include",
    )
    text = insert_after(
        text,
        "    if ((async = create_request_async( fd, get_fd_comp_flags( fd ), &req->async, 0 )))\n    {\n",
        "#ifdef WINE_IOS\n"
        "        async_set_smx_io_op( async, \"RECV\" );\n"
        "        smx_socket_io_trace( \"server-request\", \"RECV\",\n"
        "                             async_get_smx_io_async_tid( async ), current->id,\n"
        "                             async_get_smx_io_async_iosb( async ), status, 0, 0, 0,\n"
        "                             \"recv\" );\n"
        "#endif\n",
        "sock-server-recv-request",
    )
    write(path, text)


def patch_server_fd(path):
    text = read(path)
    text = insert_after(
        text,
        '#include "file.h"\n',
        "#ifdef WINE_IOS\n"
        "#include \"smx_socket_io_trace.h\"\n"
        "#endif\n",
        "fd-trace-include",
    )
    text = insert_before(
        text,
        "        fd->fd_ops->ioctl( fd, req->code, async );\n",
        "#ifdef WINE_IOS\n"
        "        if (req->code == SMX_IOCTL_AFD_POLL)\n"
        "        {\n"
        "            async_set_smx_io_op( async, \"AFD_POLL\" );\n"
        "            smx_socket_io_trace( \"server-request\", \"AFD_POLL\",\n"
        "                                 async_get_smx_io_async_tid( async ), current->id,\n"
        "                                 async_get_smx_io_async_iosb( async ),\n"
        "                                 STATUS_PENDING, 0, 0, 0, \"ioctl\" );\n"
        "        }\n"
        "#endif\n",
        "fd-server-afd-poll-request",
    )
    write(path, text)


def patch_client_unix_private(path):
    text = read(path)
    text = insert_after(
        text,
        '#include "wine/debug.h"\n',
        "#ifdef WINE_IOS\n#include \"smx_socket_io_trace.h\"\n#endif\n",
        "unix-private-trace-include",
    )
    reader = r'''#ifdef WINE_IOS
static inline BOOL smx_socket_io_get_iosb( IO_STATUS_BLOCK *io,
                                           unsigned int *status,
                                           ULONG_PTR *info )
{
    if (!io || !status || !info) return FALSE;
    if (in_wow64_call())
    {
        IO_STATUS_BLOCK32 *io32 = io->Pointer;

        if (!io32) return FALSE;
        *status = (unsigned int)ReadAcquire( &io32->Status );
        *info = io32->Information;
    }
    else
    {
        *status = (unsigned int)ReadAcquire( &io->Status );
        *info = io->Information;
    }
    return TRUE;
}
#endif

'''
    text = insert_after(
        text,
        "static inline BOOL in_wow64_call(void)\n"
        "{\n"
        "#ifdef WINE_IOS\n"
        "    if (ios_in_wow64_call) return ios_in_wow64_call();\n"
        "#endif\n"
        "    return is_win64 && is_wow64();\n"
        "}\n",
        reader,
        "unix-private-read-guest-iosb",
    )
    text = insert_before(
        text,
        "}\n\nstatic inline client_ptr_t iosb_client_ptr( IO_STATUS_BLOCK *io )",
        "#ifdef WINE_IOS\n"
        "    {\n"
        "        unsigned int written_status = STATUS_UNSUCCESSFUL;\n"
        "        ULONG_PTR written_info = 0;\n"
        "        if (in_wow64_call())\n"
        "        {\n"
        "            IO_STATUS_BLOCK32 *io = wine_server_get_ptr( iosb );\n"
        "            written_status = (unsigned int)ReadAcquire( &io->Status );\n"
        "            written_info = io->Information;\n"
        "        }\n"
        "        else\n"
        "        {\n"
        "            IO_STATUS_BLOCK *io = wine_server_get_ptr( iosb );\n"
        "            written_status = (unsigned int)ReadAcquire( &io->Status );\n"
        "            written_info = io->Information;\n"
        "        }\n"
        "        smx_socket_io_trace( \"guest-iosb-write\", \"ASYNC\", GetCurrentThreadId(), GetCurrentThreadId(),\n"
        "                             iosb, written_status, written_info,\n"
        "                             smx_socket_io_win32_error( written_status ), 0,\n"
        "                             in_wow64_call() ? \"wow64\" : \"native\" );\n"
        "    }\n"
        "#endif\n",
        "unix-private-guest-iosb-write",
    )
    write(path, text)


def patch_client_file(path):
    text = read(path)
    text = insert_before(
        text,
        "    SERVER_START_REQ( ioctl )\n    {\n        req->code        = code;\n",
        "#ifdef WINE_IOS\n"
        "    if (code == SMX_IOCTL_AFD_POLL)\n"
        "        smx_socket_io_trace( \"guest-request\", \"AFD_POLL\", GetCurrentThreadId(), GetCurrentThreadId(),\n"
        "                             iosb_client_ptr( io ),\n"
        "                             STATUS_PENDING, 0, 0, 0, \"ioctl\" );\n"
        "#endif\n",
        "client-afd-poll-request",
    )
    wait = "    if (wait_handle) status = wait_async( wait_handle, (options & FILE_SYNCHRONOUS_IO_ALERT) );\n"
    addition = ("#ifdef WINE_IOS\n"
                "    if (code == SMX_IOCTL_AFD_POLL)\n"
                "    {\n"
                "        unsigned int guest_status = STATUS_UNSUCCESSFUL;\n"
                "        ULONG_PTR guest_info = 0;\n"
                "        if (!smx_socket_io_get_iosb( io, &guest_status, &guest_info ))\n"
                "            guest_status = STATUS_UNSUCCESSFUL;\n"
                "        smx_socket_io_trace( \"guest-result\", \"AFD_POLL\", GetCurrentThreadId(), GetCurrentThreadId(),\n"
                "                             iosb_client_ptr( io ),\n"
                "                             guest_status, guest_info,\n"
                "                             smx_socket_io_win32_error( guest_status ), status,\n"
                "                             \"ioctl\" );\n"
                "    }\n"
                "#endif\n")
    text = insert_after_in_function(
        text,
        "static NTSTATUS server_ioctl_file(",
        wait,
        addition,
        "client-afd-poll-result",
    )
    write(path, text)


def patch_client_socket(path):
    text = read(path)
    text = insert_before(
        text,
        "    SERVER_START_REQ( recv_socket )\n    {\n        req->force_async = force_async;\n",
        "#ifdef WINE_IOS\n"
        "    smx_socket_io_trace( \"guest-request\", \"RECV\", GetCurrentThreadId(), GetCurrentThreadId(),\n"
        "                         iosb_client_ptr( io ),\n"
        "                         STATUS_PENDING, 0, 0, 0, \"recv\" );\n"
        "#endif\n",
        "client-recv-request",
    )
    wait = "    if (wait_handle) status = wait_async( wait_handle, options & FILE_SYNCHRONOUS_IO_ALERT );\n"
    addition = ("#ifdef WINE_IOS\n"
                "    {\n"
                "        unsigned int guest_status = STATUS_UNSUCCESSFUL;\n"
                "        ULONG_PTR guest_info = 0;\n"
                "        if (!smx_socket_io_get_iosb( io, &guest_status, &guest_info ))\n"
                "            guest_status = STATUS_UNSUCCESSFUL;\n"
                "        smx_socket_io_trace( \"guest-result\", \"RECV\", GetCurrentThreadId(), GetCurrentThreadId(),\n"
                "                             iosb_client_ptr( io ),\n"
                "                             guest_status, guest_info,\n"
                "                             smx_socket_io_win32_error( guest_status ), status,\n"
                "                             \"recv\" );\n"
                "    }\n"
                "#endif\n")
    text = insert_after_in_function(
        text,
        "static NTSTATUS sock_recv(",
        wait,
        addition,
        "client-recv-result",
    )
    write(path, text)


def main(argv):
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} PRODUCT_ROOT|WINE_ROOT", file=sys.stderr)
        return 64
    argument = Path(argv[1]).resolve()
    if (argument / "server").is_dir() and (argument / "dlls").is_dir():
        wine = argument
        root = argument.parent
    else:
        root = argument
        wine = root / "wine"
    if not wine.is_dir():
        print(f"missing Wine tree: {wine}", file=sys.stderr)
        return 66

    targets = [
        wine / "server/file.h",
        wine / "server/async.c",
        wine / "server/thread.c",
        wine / "server/sock.c",
        wine / "server/fd.c",
        wine / "dlls/ntdll/unix/unix_private.h",
        wine / "dlls/ntdll/unix/file.c",
        wine / "dlls/ntdll/unix/socket.c",
        root / "build/wineserver/fd_ios.c",
    ]
    helpers = [
        (wine / "server/smx_socket_io_trace.h", SERVER_HELPER),
        (wine / "dlls/ntdll/unix/smx_socket_io_trace.h", CLIENT_HELPER),
    ]
    already = all(MARKER in read(path) for path in targets) and all(
        helper.is_file() and read(helper) == content for helper, content in helpers
    )
    if already:
        print("SMX socket I/O trace: already applied (diagnostic only; enable with MADEIRA_SMX_IO_TRACE=1)")
        return 0

    patch_server_file_h(wine / "server/file.h")
    patch_server_async(wine / "server/async.c")
    patch_server_thread(wine / "server/thread.c")
    patch_server_sock(wine / "server/sock.c")
    patch_server_fd(wine / "server/fd.c")
    patch_server_fd(root / "build/wineserver/fd_ios.c")
    patch_client_unix_private(wine / "dlls/ntdll/unix/unix_private.h")
    patch_client_file(wine / "dlls/ntdll/unix/file.c")
    patch_client_socket(wine / "dlls/ntdll/unix/socket.c")

    write(wine / "server/smx_socket_io_trace.h", SERVER_HELPER)
    write(wine / "dlls/ntdll/unix/smx_socket_io_trace.h", CLIENT_HELPER)

    print("SMX socket I/O trace: applied (diagnostic only; enable with MADEIRA_SMX_IO_TRACE=1)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
