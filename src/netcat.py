#!/usr/bin/env python
import socket, sys, argparse, threading, subprocess

CMD_ACTION = "cmd"

def main():
    port = 0
    target = ""
    listen = False
    args = sys.argv[1:]
    #parser = argparse.ArgumentParse(description="A python implementation of some of netcats functionality")
    #parser.add_argument()
    #parser.add_argument()
    #parser.add_argument()
    #parser.add_argument()
    #parser.add_argument()
    if args[0] == "-t":
        client(args[1], args[2], CMD_ACTION)
    else:
        server(args[1], args[2], CMD_ACTION)

def server(ip, port, action):
    try:
        if len(ip) == 0:
            ip = "0.0.0.0"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((ip, int(port)))
        sock.listen(10)
        print "Connected to " + ip +" at port " + port 
        while True:
            cli_sock, addr = sock.accept()
            cli_thread = threading.Thread(target=handler, args=(cli_sock, action))
            cli_thread.start()
    except:
        sock.close()

def handler(cli_sock, action):
    if action == CMD_ACTION:
        
        while True:
            cmd = ""
            cli_sock.send("#> ")
            while "\n" not in cmd:
                cmd += cli_sock.recv(1024)
            cmd_output = run_command(cmd)
            cli_sock.send(cmd_output)

def run_command(cmd):
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out = proc.stdout.read()
    return out
            
    


def client(ip, port, action):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, int(port)))
        while True:
            out_buf = "" 
            while True:
                out = sock.recv(1024)
                out_buf += out
                if len(out) < 1024:
                    break
            print out_buf
            cmd = raw_input()
            sock.send(cmd + "\n")
    except:    
        sock.close()


main()        
