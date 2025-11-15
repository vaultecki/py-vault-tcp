#!/usr/bin/env python3
"""Vault TCP using Noise protocol (optimized)

Features:
- Length-prefixed framing (4 bytes, big-endian)
- Threaded multi-client server
- Robust handshake loops
- Logging and explicit error handling
- Callbacks for received messages (no PySignal dependency)
- Clean close/cleanup
"""

from __future__ import annotations
import socket
import threading
import struct
import logging
import typing as t

import noise.connection

# Logging configuration (caller can reconfigure)
logger = logging.getLogger("vault_tcp")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


class VaultProtocolError(Exception):
    pass


def _recv_exact(sock: socket.socket, n: int, timeout: t.Optional[float] = None) -> bytes:
    """Read exactly n bytes from socket or raise EOFError."""
    sock.settimeout(timeout)
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise EOFError("Socket closed while reading")
        data.extend(chunk)
    return bytes(data)


class VaultConnection:
    """
    Encapsulates a single connection (socket + noise proto).
    Not thread-safe except for send() which acquires a lock.
    """

    def __init__(
        self,
        sock: socket.socket,
        proto_name: str,
        is_initiator: bool,
        max_message_size: int = 64 * 1024,
        timeout: float = 10.0,
    ):
        self.sock = sock
        self.sock.settimeout(timeout)
        self.timeout = timeout
        self.max_message_size = max_message_size
        self._send_lock = threading.Lock()
        # prepare noise proto instance
        self.proto = noise.connection.NoiseConnection.from_name(proto_name.encode("utf-8"))
        if is_initiator:
            self.proto.set_as_initiator()
        else:
            self.proto.set_as_responder()

    def do_handshake(self) -> None:
        """Perform handshake loop until proto.handshake_finished is True or error."""
        self.proto.start_handshake()
        try:
            # Handshake loop: alternate send/receive until finished.
            while not self.proto.handshake_finished:
                # If proto wants to write a message, write it.
                try:
                    msg = self.proto.write_message()
                except Exception:
                    msg = b""
                if msg:
                    self.sock.sendall(msg)

                if self.proto.handshake_finished:
                    break

                # Attempt to receive data for handshake
                # read some bytes (Noise handshake messages are small; we use 2048)
                data = _recv_exact(self.sock, 1, timeout=self.timeout)
                # we already read one byte; now try to read rest available (non-blocking chunk)
                # read up to 2047 more bytes (best-effort). If no more data quickly, continue.
                remaining = bytearray(data)
                try:
                    self.sock.settimeout(0.05)
                    while True:
                        chunk = self.sock.recv(2047)
                        if not chunk:
                            break
                        remaining.extend(chunk)
                except socket.timeout:
                    pass
                finally:
                    self.sock.settimeout(self.timeout)
                self.proto.read_message(bytes(remaining))
        except EOFError:
            raise VaultProtocolError("Connection closed during handshake")
        except Exception as e:
            raise VaultProtocolError(f"Handshake failed: {e}")

    def send(self, plaintext: bytes) -> None:
        """Encrypt and send a single framed message."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        if len(plaintext) > self.max_message_size:
            raise ValueError("message exceeds max_message_size")
        with self._send_lock:
            try:
                ciphertext = self.proto.encrypt(bytes(plaintext))
            except Exception as e:
                raise VaultProtocolError(f"Encryption failed: {e}")
            # frame: 4-byte length + payload
            header = struct.pack("!I", len(ciphertext))
            try:
                self.sock.sendall(header + ciphertext)
            except Exception as e:
                raise VaultProtocolError(f"Send failed: {e}")

    def receive(self) -> bytes:
        """Receive a single framed message, decrypt and return plaintext."""
        # read 4-byte length
        try:
            header = _recv_exact(self.sock, 4, timeout=self.timeout)
        except EOFError:
            raise VaultProtocolError("Connection closed while reading length")
        except Exception as e:
            raise VaultProtocolError(f"Failed to read message length: {e}")

        (length,) = struct.unpack("!I", header)
        if length <= 0 or length > self.max_message_size + 16 * 1024:
            raise VaultProtocolError(f"Invalid message length: {length}")

        try:
            ciphertext = _recv_exact(self.sock, length, timeout=self.timeout)
        except EOFError:
            raise VaultProtocolError("Connection closed while reading payload")
        except Exception as e:
            raise VaultProtocolError(f"Failed to read payload: {e}")

        try:
            plaintext = self.proto.decrypt(ciphertext)
        except Exception as e:
            raise VaultProtocolError(f"Decryption failed: {e}")
        return plaintext

    def close(self) -> None:
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass


class VaultTCPServer:
    """
    Threaded multi-client server using VaultConnection per client.

    - on_message callback: callable(conn_id: int, plaintext: bytes, conn: VaultConnection)
    """

    def __init__(
        self,
        listen_ip: str = "0.0.0.0",
        listen_port: int = 5004,
        proto_name: str = "Noise_NN_25519_AESGCM_SHA512",
        max_message_size: int = 64 * 1024,
        timeout: float = 10.0,
    ):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.proto_name = proto_name
        self.max_message_size = max_message_size
        self.timeout = timeout

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.listen_ip, self.listen_port))
        self._server_sock.listen()
        self._accept_thread: t.Optional[threading.Thread] = None
        self._running = threading.Event()
        self._next_conn_id = 1
        self._conns_lock = threading.Lock()
        self._connections: t.Dict[int, VaultConnection] = {}

        # callback placeholder
        self.on_message: t.Callable[[int, bytes, VaultConnection], None] = lambda *_: None
        self.on_connect: t.Callable[[int], None] = lambda _: None
        self.on_disconnect: t.Callable[[int], None] = lambda _: None

    def start(self) -> None:
        if self._accept_thread and self._accept_thread.is_alive():
            return
        self._running.set()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        logger.info("Server started on %s:%d", self.listen_ip, self.listen_port)

    def _accept_loop(self) -> None:
        while self._running.is_set():
            try:
                client_sock, addr = self._server_sock.accept()
                logger.info("Accepted connection from %s", addr)
                threading.Thread(target=self._handle_new_client, args=(client_sock,), daemon=True).start()
            except Exception as e:
                if self._running.is_set():
                    logger.exception("Accept loop error: %s", e)

    def _handle_new_client(self, client_sock: socket.socket) -> None:
        conn_id = 0
        try:
            conn = VaultConnection(client_sock, self.proto_name, is_initiator=False,
                                   max_message_size=self.max_message_size, timeout=self.timeout)
            conn.do_handshake()

            with self._conns_lock:
                conn_id = self._next_conn_id
                self._next_conn_id += 1
                self._connections[conn_id] = conn

            self.on_connect(conn_id)
            logger.info("Handshake finished for conn %d", conn_id)

            # message loop
            while True:
                try:
                    plaintext = conn.receive()
                except VaultProtocolError as e:
                    logger.info("Connection %d closed or protocol error: %s", conn_id, e)
                    break
                # deliver to callback
                try:
                    self.on_message(conn_id, plaintext, conn)
                except Exception:
                    logger.exception("on_message callback failed for conn %d", conn_id)
        except Exception as e:
            logger.exception("Failed to establish connection: %s", e)
        finally:
            if conn_id:
                with self._conns_lock:
                    if conn_id in self._connections:
                        try:
                            self._connections[conn_id].close()
                        except Exception:
                            pass
                        del self._connections[conn_id]
                self.on_disconnect(conn_id)
                logger.info("Connection %d cleaned up", conn_id)
            else:
                try:
                    client_sock.close()
                except Exception:
                    pass

    def send_to(self, conn_id: int, data: bytes) -> None:
        with self._conns_lock:
            conn = self._connections.get(conn_id)
        if not conn:
            raise KeyError(f"No such connection: {conn_id}")
        conn.send(data)

    def broadcast(self, data: bytes) -> None:
        with self._conns_lock:
            conns = list(self._connections.items())
        for cid, conn in conns:
            try:
                conn.send(data)
            except Exception:
                logger.exception("Broadcast send failed for %d", cid)

    def close(self) -> None:
        self._running.clear()
        try:
            self._server_sock.close()
        except Exception:
            pass
        with self._conns_lock:
            conns = list(self._connections.items())
            self._connections.clear()
        for cid, conn in conns:
            try:
                conn.close()
            except Exception:
                pass
        logger.info("Server shutdown")


class VaultTCPClient:
    """
    Simple client wrapper.
    - connect() performs handshake
    - send()/receive() operate on the secure channel
    """

    def __init__(
        self,
        server_ip: str = "127.0.0.1",
        server_port: int = 5004,
        proto_name: str = "Noise_NN_25519_AESGCM_SHA512",
        max_message_size: int = 64 * 1024,
        timeout: float = 10.0,
    ):
        self.server_ip = server_ip
        self.server_port = server_port
        self.proto_name = proto_name
        self.max_message_size = max_message_size
        self.timeout = timeout
        self._sock: t.Optional[socket.socket] = None
        self._conn: t.Optional[VaultConnection] = None

    def connect(self) -> None:
        if self._sock:
            raise RuntimeError("Already connected")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.server_ip, self.server_port))
        self._sock = s
        self._conn = VaultConnection(s, self.proto_name, is_initiator=True,
                                     max_message_size=self.max_message_size, timeout=self.timeout)
        self._conn.do_handshake()
        logger.info("Client handshake finished")

    def send(self, data: bytes) -> None:
        if not self._conn:
            raise RuntimeError("Not connected")
        self._conn.send(data)

    def receive(self) -> bytes:
        if not self._conn:
            raise RuntimeError("Not connected")
        return self._conn.receive()

    def send_and_receive(self, data: bytes) -> bytes:
        """Send then blockingly wait for one response."""
        self.send(data)
        return self.receive()

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        logger.info("Client closed")


# Example usage (only for quick local testing)
if __name__ == "__main__":
    import time

    def on_msg(conn_id, payload: bytes, conn_obj: VaultConnection):
        logger.info("Server got from %d: %s", conn_id, payload.decode("utf-8", errors="ignore"))
        # echo back
        try:
            conn_obj.send(b"ECHO: " + payload)
        except Exception:
            logger.exception("Failed to echo")

    server = VaultTCPServer(listen_ip="127.0.0.1", listen_port=5004)
    server.on_message = on_msg
    server.start()

    # small client test
    client = VaultTCPClient(server_ip="127.0.0.1", server_port=5004)
    client.connect()
    resp = client.send_and_receive(b"hello server")
    logger.info("Client received: %s", resp.decode("utf-8", errors="ignore"))
    client.close()

    # shutdown server
    server.close()
    time.sleep(0.2)
