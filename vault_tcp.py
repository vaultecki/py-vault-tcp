
import itertools
import json
import time

import noise.connection
import socket
import PySignal


class VaultSocket:
    recv_data = PySignal.ClassSignal()

    def __init__(self, client, ip='localhost', port=5004, proto_name="Noise_NN_25519_AESGCM_SHA512", timeout=10):
        # init socket
        self.socket = socket.socket()
        self.timeout = timeout
        # create noise instance
        self.name_noise_connection_bytes = proto_name.encode("utf-8")
        self.proto = noise.connection.NoiseConnection.from_name(self.name_noise_connection_bytes)
        self.max_byte = 8000

        self.client = client
        if client == "client":
            self.client_init(ip, port)
        if client == "server":
            self.server = {}
            self.server_init(ip, port)

    def client_init(self, ip='localhost', port=5004):
        # connect to ip/port
        self.socket.settimeout(self.timeout)
        self.socket.connect((ip, port))
        # this side initiate connection (client)
        self.proto.set_as_initiator()
        # do the handshake
        self.hand_shake()
        return 1

    def send(self, msg, conn=-1):
        print("try to send: {}".format(msg))
        # create bytestring
        if type(msg) != str and type(msg) != bytes:
            msg = "{}".format(msg)
        if type(msg) == str:
            msg = msg.encode("utf-8")
        if not type(msg) == bytes:
            raise TypeError("Message can not be converted to bytes")
        if len(msg) > self.max_byte:
            raise BufferError("Message to large to handle")
        msg_byte = msg
        if self.client == "client":
            # create encrypted message
            msg_encrypted = self.proto.encrypt(msg_byte)
            # send encrypted message to other side
            self.socket.sendall(msg_encrypted)
            self.receive(conn)
        if self.client == "server":
            proto = self.server.get(conn, -1)
            if proto == -1:
                return -1
            # create encrypted message
            msg_encrypted = proto.encrypt(msg_byte)
            # send encrypted message to other side
            conn.sendall(msg_encrypted)
        return 1

    def receive(self, conn=-1):
        if self.client == "client":
            # receive data
            data = self.socket.recv(self.max_byte)
            # decrypt data
            msg_recv = self.proto.decrypt(data).decode('utf-8')
            self.recv_data.emit(msg_recv, conn)
            return msg_recv
        if self.client == "server":
            proto = self.server.get(conn, -1)
            if proto == -1:
                return -1
            # receive data
            data = conn.recv(self.max_byte)
            if not data:
                return -1
            # decrypt data
            msg_recv = proto.decrypt(data).decode("utf-8")
            print("msg recv: {}".format(msg_recv))
            self.recv_data.emit(msg_recv, conn)
            return msg_recv
        return -1

    def server_init(self, ip='localhost', port=5004):
        # init socket
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # bind to ip/port
        self.socket.bind((ip, port))
        # this side waits for connections
        self.proto.set_as_responder()
        return 1

    def hand_shake(self, conn=-1):
        if self.client == "client":
            # first start the handshake
            self.proto.start_handshake()
            # send unencrypted message to complete handshake
            msg = self.proto.write_message()
            self.socket.sendall(msg)
            # receive answer ad end handshake
            data = self.socket.recv(2048)
            msg_recv = self.proto.read_message(data)
        if self.client == "server":
            # get noise proto for conn
            proto = self.server.get(conn, -1)
            if proto == -1:
                return -1
            # first start the handshake
            proto.start_handshake()
            # Perform handshake. Break when finished
            for action in itertools.cycle(['receive', 'send']):
                if proto.handshake_finished:
                    break
                elif action == 'send':
                    msg = proto.write_message()
                    conn.sendall(msg)
                elif action == 'receive':
                    data = conn.recv(2048)
                    msg_recv = proto.read_message(data)
        return 1

    def server_listen(self):
        print("server noise listen")
        # listen on socket
        self.socket.listen(1)
        # get connection/ip from incomming
        conn, addr = self.socket.accept()
        # create noise instance
        proto = noise.connection.NoiseConnection.from_name(self.name_noise_connection_bytes)
        # this side waits for connections
        proto.set_as_responder()
        self.server.update({conn: proto})
        # do the handshake
        self.hand_shake(conn)
        # loop "echoing" received data
        while True:
            msg_recv = self.receive(conn)
            if msg_recv == -1:
                break


if __name__ == "__main__":
    # print("Testing")
    pass
