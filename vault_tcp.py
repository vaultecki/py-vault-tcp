# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

"""Vault TCP using Noise protocol (production-ready)

Features:
- Length-prefixed framing (4 bytes, big-endian)
- Threaded multi-client server
- Robust handshake with proper error handling
- Comprehensive logging
- Callbacks for received messages
- Context manager support
- Graceful shutdown
- Connection timeouts and idle detection
"""

from __future__ import annotations

import contextlib
import logging
import socket
import struct
import threading
import time
import typing as t

import noise.connection

# Logging configuration
logger = logging.getLogger("vault_tcp")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Constants
# Fixed by the Noise Protocol Framework spec (section 5, "AEAD"): both cipher
# functions it defines - AESGCM and ChaChaPoly, the only two the noiseprotocol
# library implements - always produce a 16-byte authentication tag, so
# ciphertext is always exactly 16 bytes longer than the plaintext regardless
# of which of the two is negotiated via proto_name. This is not a guess to be
# kept in sync with proto_name; it would only need to change if a future
# Noise cipher function with a different tag size were added and used here.
NOISE_AEAD_OVERHEAD = 16
DEFAULT_HANDSHAKE_TIMEOUT = 10.0
DEFAULT_MESSAGE_TIMEOUT = 30.0
DEFAULT_IDLE_TIMEOUT = 300.0  # 5 minutes


class VaultProtocolError(Exception):
    """Raised when protocol-level errors occur."""

    pass


class VaultHandshakeError(VaultProtocolError):
    """Raised when handshake fails."""

    pass


class VaultConnectionClosed(VaultProtocolError):
    """Raised when connection is closed unexpectedly."""

    pass


def _recv_exact(sock: socket.socket, n: int, timeout: float | None = None) -> bytes:
    """
    Read exactly n bytes from socket.

    A TCP stream has no message boundaries: if a timeout hits after some
    (but not all) bytes of the frame have already been consumed from the
    socket, those bytes cannot be put back. Retrying would read the next
    reply as if it were still part of the current frame's header/payload,
    silently desynchronizing framing forever. So a partial-read timeout is
    reported as VaultProtocolError (caller must close the connection),
    while a timeout with zero bytes read yet is a plain TimeoutError that
    is safe to retry (e.g. for idle-connection polling).

    Raises:
        TimeoutError: Timed out before any bytes of this frame arrived.
        VaultProtocolError: Timed out after partially reading the frame.
        EOFError: Socket closed before n bytes were read.
    """
    sock.settimeout(timeout)
    data = bytearray()
    while len(data) < n:
        try:
            chunk = sock.recv(n - len(data))
        except TimeoutError as e:
            if data:
                raise VaultProtocolError(
                    f"Timed out after reading {len(data)}/{n} bytes; "
                    "connection framing is desynchronized"
                ) from e
            raise TimeoutError(f"Timeout while reading {n} bytes") from e
        if not chunk:
            raise EOFError("Socket closed while reading")
        data.extend(chunk)
    return bytes(data)


class VaultConnection:
    """
    Encapsulates a single connection (socket + noise protocol).

    Thread-safe for send() operations (uses internal lock).
    Not thread-safe for receive() - should be called from single thread.
    """

    def __init__(
        self,
        sock: socket.socket,
        proto_name: str,
        is_initiator: bool,
        max_message_size: int = 64 * 1024,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        message_timeout: float = DEFAULT_MESSAGE_TIMEOUT,
        static_key: bytes | None = None,
        remote_static: bytes | None = None,
    ):
        """
        Initialize a VaultConnection.

        Args:
            sock: Connected socket
            proto_name: Noise protocol name (e.g., "Noise_NN_25519_AESGCM_SHA512")
            is_initiator: True if this side initiates handshake
            max_message_size: Maximum plaintext message size
            handshake_timeout: Timeout for handshake operations
            message_timeout: Timeout for message send/receive
            static_key: Optional static private key (32 bytes for 25519)
            remote_static: Optional remote static public key
        """
        self.sock = sock
        self.handshake_timeout = handshake_timeout
        self.message_timeout = message_timeout
        self.max_message_size = max_message_size
        self._is_initiator = is_initiator
        self._send_lock = threading.Lock()
        self._handshake_complete = False
        self._closed = False

        # Statistics
        self._bytes_sent = 0
        self._bytes_received = 0
        self._messages_sent = 0
        self._messages_received = 0
        self._created_at = time.time()

        # Initialize Noise protocol
        self.proto = noise.connection.NoiseConnection.from_name(proto_name.encode("utf-8"))

        if is_initiator:
            self.proto.set_as_initiator()
        else:
            self.proto.set_as_responder()

        # Set static keys if provided
        if static_key:
            self.proto.set_keypair_from_private_bytes(noise.connection.Keypair.STATIC, static_key)

        if remote_static:
            self.proto.set_keypair_from_public_bytes(
                noise.connection.Keypair.REMOTE_STATIC, remote_static
            )

    def do_handshake(self) -> None:
        """
        Perform Noise protocol handshake.

        Raises:
            VaultHandshakeError: If handshake fails
            TimeoutError: If handshake times out
        """
        if self._handshake_complete:
            raise VaultHandshakeError("Handshake already completed")

        self.sock.settimeout(self.handshake_timeout)

        try:
            self.proto.start_handshake()

            # Noise handshake messages strictly alternate direction, starting
            # with the initiator's first write. Tracking turns explicitly (rather
            # than probing write_message()/read_message() speculatively) is
            # required: the underlying library raises if called out of turn.
            my_turn_to_write = self._is_initiator

            # Handshake loop: exchange messages until complete
            while not self.proto.handshake_finished:
                if my_turn_to_write:
                    try:
                        msg = self.proto.write_message()
                    except Exception as e:
                        raise VaultHandshakeError(f"Failed to build handshake message: {e}") from e

                    try:
                        self.sock.sendall(msg)
                    except Exception as e:
                        raise VaultHandshakeError(f"Failed to send handshake message: {e}") from e
                else:
                    # Read response (Noise handshake messages are small, typically < 1KB)
                    try:
                        data = self.sock.recv(4096)
                    except TimeoutError as e:
                        raise TimeoutError("Timeout waiting for handshake message") from e
                    except Exception as e:
                        raise VaultHandshakeError(
                            f"Failed to receive handshake message: {e}"
                        ) from e

                    if not data:
                        raise VaultHandshakeError("Connection closed during handshake")

                    try:
                        self.proto.read_message(data)
                    except Exception as e:
                        raise VaultHandshakeError(
                            f"Failed to process handshake message: {e}"
                        ) from e

                my_turn_to_write = not my_turn_to_write

            # Verify handshake completed successfully
            if not self.proto.handshake_finished:
                raise VaultHandshakeError("Handshake did not complete properly")

            self._handshake_complete = True
            logger.debug("Handshake completed successfully")

        except (VaultHandshakeError, TimeoutError):
            raise
        except Exception as e:
            raise VaultHandshakeError(f"Unexpected handshake error: {e}") from e
        finally:
            # Reset timeout for normal operations
            self.sock.settimeout(self.message_timeout)

    def send(self, plaintext: bytes) -> None:
        """
        Encrypt and send a single framed message.

        Thread-safe.

        Args:
            plaintext: Message to send (bytes)

        On any encryption or transport failure the connection is closed: the
        Noise cipher's nonce counter advances on every encrypt() call, so a
        message that fails to actually reach the peer (partial write, dead
        socket, ...) leaves both sides' nonce counters out of sync. Continuing
        to use the connection afterwards would silently corrupt every
        subsequent message, so it must not be reused - open a new one instead.

        Raises:
            VaultProtocolError: If encryption or sending fails (connection is
                closed as part of raising this)
            ValueError: If message exceeds max size
            TypeError: If plaintext is not bytes
        """
        if self._closed:
            raise VaultProtocolError("Connection is closed")

        if not self._handshake_complete:
            raise VaultProtocolError("Handshake not completed")

        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")

        if len(plaintext) > self.max_message_size:
            raise ValueError(
                f"Message size {len(plaintext)} exceeds maximum {self.max_message_size}"
            )

        with self._send_lock:
            try:
                ciphertext = self.proto.encrypt(bytes(plaintext))
            except Exception as e:
                self.close()
                raise VaultProtocolError(f"Encryption failed: {e}") from e

            # Frame: 4-byte length (big-endian) + ciphertext
            header = struct.pack("!I", len(ciphertext))
            frame = header + ciphertext

            try:
                self.sock.sendall(frame)
                self._bytes_sent += len(frame)
                self._messages_sent += 1
            except Exception as e:
                self.close()
                raise VaultProtocolError(f"Send failed: {e}") from e

    def receive(self, timeout: float | None = None) -> bytes:
        """
        Receive a single framed message and decrypt.

        Not thread-safe - should be called from single thread only.

        Args:
            timeout: Total time budget for reading this message (header and
                payload combined). Defaults to message_timeout. Overriding it
                lets a caller (e.g. VaultTCPServer, for idle-connection
                polling) poll more or less often than message_timeout without
                that also being the per-connect message_timeout default.

        Returns:
            Decrypted plaintext message

        A TimeoutError raised before any bytes of the next frame arrived is
        safe to retry (used by the server for idle-connection polling). Every
        other failure - partial-read desync, invalid framing, or a decrypt
        failure (which may indicate nonce desync or tampering) - closes the
        connection, since the byte stream or cipher state can no longer be
        trusted afterwards.

        Raises:
            VaultProtocolError: If receiving or decryption fails (connection
                is closed as part of raising this)
            VaultConnectionClosed: If connection closed (connection is closed
                as part of raising this)
            TimeoutError: If no data arrived yet; connection remains usable
        """
        if self._closed:
            raise VaultProtocolError("Connection is closed")

        if not self._handshake_complete:
            raise VaultProtocolError("Handshake not completed")

        # Header and payload share a single deadline instead of each getting
        # their own full timeout - otherwise one receive() call could block
        # for up to 2x the configured timeout.
        deadline = time.monotonic() + (self.message_timeout if timeout is None else timeout)

        # Read 4-byte length header
        try:
            header = _recv_exact(self.sock, 4, timeout=max(0.0, deadline - time.monotonic()))
        except EOFError as e:
            self.close()
            raise VaultConnectionClosed("Connection closed while reading length") from e
        except TimeoutError:
            raise
        except VaultProtocolError:
            self.close()
            raise
        except Exception as e:
            self.close()
            raise VaultProtocolError(f"Failed to read message length: {e}") from e

        (length,) = struct.unpack("!I", header)

        # Validate length
        max_ciphertext_size = self.max_message_size + NOISE_AEAD_OVERHEAD
        if length <= 0 or length > max_ciphertext_size:
            self.close()
            raise VaultProtocolError(
                f"Invalid message length: {length} (max: {max_ciphertext_size})"
            )

        # Read payload. Unlike the header read above, a timeout here is never
        # safe to treat as "no activity yet, retry" even if zero payload
        # bytes have arrived: the header has already been consumed from the
        # stream, so abandoning this read would desync the next receive()
        # call's attempt to read a fresh header from what is actually still
        # this message's payload.
        try:
            remaining = max(0.0, deadline - time.monotonic())
            ciphertext = _recv_exact(self.sock, length, timeout=remaining)
        except EOFError as e:
            self.close()
            raise VaultConnectionClosed("Connection closed while reading payload") from e
        except TimeoutError as e:
            self.close()
            raise VaultProtocolError(
                "Timed out waiting for payload after the header was already "
                "read; connection framing is desynchronized"
            ) from e
        except VaultProtocolError:
            self.close()
            raise
        except Exception as e:
            self.close()
            raise VaultProtocolError(f"Failed to read payload: {e}") from e

        # Decrypt
        try:
            plaintext = bytes(self.proto.decrypt(ciphertext))
        except Exception as e:
            self.close()
            raise VaultProtocolError(f"Decryption failed: {e}") from e

        self._bytes_received += len(header) + len(ciphertext)
        self._messages_received += 1

        return plaintext

    def get_stats(self) -> dict[str, t.Any]:
        """Get connection statistics."""
        return {
            "bytes_sent": self._bytes_sent,
            "bytes_received": self._bytes_received,
            "messages_sent": self._messages_sent,
            "messages_received": self._messages_received,
            "uptime_seconds": time.time() - self._created_at,
            "handshake_complete": self._handshake_complete,
            "closed": self._closed,
        }

    def close(self) -> None:
        """Close the connection gracefully."""
        if self._closed:
            return

        self._closed = True

        with contextlib.suppress(Exception):
            self.sock.shutdown(socket.SHUT_RDWR)

        with contextlib.suppress(Exception):
            self.sock.close()

    def __enter__(self) -> VaultConnection:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: t.Any,
    ) -> t.Literal[False]:
        """Context manager exit."""
        self.close()
        return False


class VaultTCPServer:
    """
    Threaded multi-client server using VaultConnection per client.

    Callbacks:
        on_message(conn_id: int, plaintext: bytes, conn: VaultConnection) -> None
        on_connect(conn_id: int) -> None
        on_disconnect(conn_id: int) -> None
    """

    def __init__(
        self,
        listen_ip: str = "0.0.0.0",
        listen_port: int = 5004,
        proto_name: str = "Noise_NN_25519_AESGCM_SHA512",
        max_message_size: int = 64 * 1024,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        message_timeout: float = DEFAULT_MESSAGE_TIMEOUT,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT,
    ):
        """
        Initialize VaultTCPServer.

        Args:
            listen_ip: IP address to bind to
            listen_port: Port to listen on
            proto_name: Noise protocol name
            max_message_size: Maximum plaintext message size
            handshake_timeout: Timeout for handshake
            message_timeout: Timeout for message operations
            idle_timeout: Timeout for idle connections (0 to disable)
        """
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.proto_name = proto_name
        self.max_message_size = max_message_size
        self.handshake_timeout = handshake_timeout
        self.message_timeout = message_timeout
        self.idle_timeout = idle_timeout

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.listen_ip, self.listen_port))
        self._server_sock.listen(5)

        self._accept_thread: threading.Thread | None = None
        self._running = threading.Event()
        self._next_conn_id = 1
        self._conns_lock = threading.Lock()
        self._connections: dict[int, VaultConnection] = {}

        # Callbacks (set these before calling start())
        self.on_message: t.Callable[[int, bytes, VaultConnection], None] | None = None
        self.on_connect: t.Callable[[int], None] | None = None
        self.on_disconnect: t.Callable[[int], None] | None = None

    def start(self) -> None:
        """Start the server (non-blocking)."""
        if self._accept_thread and self._accept_thread.is_alive():
            logger.warning("Server already running")
            return

        self._running.set()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        logger.info("Server started on %s:%d", self.listen_ip, self.listen_port)

    def _accept_loop(self) -> None:
        """Accept incoming connections."""
        while self._running.is_set():
            try:
                # Use timeout to periodically check _running flag
                self._server_sock.settimeout(1.0)
                try:
                    client_sock, addr = self._server_sock.accept()
                except TimeoutError:
                    continue

                logger.info("Accepted connection from %s", addr)
                threading.Thread(
                    target=self._handle_new_client, args=(client_sock, addr), daemon=True
                ).start()
            except Exception as e:
                if self._running.is_set():
                    logger.exception("Accept loop error: %s", e)

    def _handle_new_client(self, client_sock: socket.socket, addr: tuple[str, int]) -> None:
        """Handle a new client connection."""
        conn_id = 0
        conn = None

        try:
            # Create connection and perform handshake
            conn = VaultConnection(
                client_sock,
                self.proto_name,
                is_initiator=False,
                max_message_size=self.max_message_size,
                handshake_timeout=self.handshake_timeout,
                message_timeout=self.message_timeout,
            )

            conn.do_handshake()

            # Register connection
            with self._conns_lock:
                conn_id = self._next_conn_id
                self._next_conn_id += 1
                self._connections[conn_id] = conn

            logger.info("Connection %d established from %s", conn_id, addr)

            # Call on_connect callback
            if self.on_connect:
                try:
                    self.on_connect(conn_id)
                except Exception:
                    logger.exception("on_connect callback failed for conn %d", conn_id)

            # Message receive loop with idle timeout. When idle_timeout is
            # shorter than message_timeout, poll at idle_timeout's cadence
            # instead of waiting a full message_timeout between idle checks
            # (that would delay disconnecting an idle client by up to
            # message_timeout - idle_timeout seconds). This also caps how
            # long a single message transfer on this connection may take.
            poll_timeout = self.message_timeout
            if self.idle_timeout > 0:
                poll_timeout = min(self.message_timeout, self.idle_timeout)

            last_activity = time.time()

            while self._running.is_set():
                try:
                    plaintext = conn.receive(timeout=poll_timeout)
                    last_activity = time.time()

                    # Deliver to callback
                    if self.on_message:
                        try:
                            self.on_message(conn_id, plaintext, conn)
                        except Exception:
                            logger.exception("on_message callback failed for conn %d", conn_id)

                except TimeoutError:
                    # Check idle timeout
                    if self.idle_timeout > 0:
                        idle_time = time.time() - last_activity
                        if idle_time > self.idle_timeout:
                            logger.info("Connection %d idle timeout (%.1fs)", conn_id, idle_time)
                            break
                    continue

                except VaultConnectionClosed as e:
                    logger.info("Connection %d closed: %s", conn_id, e)
                    break

                except VaultProtocolError as e:
                    logger.warning("Protocol error on connection %d: %s", conn_id, e)
                    break

        except VaultHandshakeError as e:
            logger.warning("Handshake failed from %s: %s", addr, e)

        except Exception as e:
            logger.exception("Unexpected error handling connection from %s: %s", addr, e)

        finally:
            # Cleanup
            if conn_id:
                with self._conns_lock:
                    if conn_id in self._connections:
                        with contextlib.suppress(Exception):
                            self._connections[conn_id].close()
                        del self._connections[conn_id]

                # Call on_disconnect callback
                if self.on_disconnect:
                    try:
                        self.on_disconnect(conn_id)
                    except Exception:
                        logger.exception("on_disconnect callback failed for conn %d", conn_id)

                logger.info("Connection %d cleaned up", conn_id)
            else:
                # Handshake failed, close socket directly
                with contextlib.suppress(Exception):
                    client_sock.close()

    def send_to(self, conn_id: int, data: bytes) -> None:
        """
        Send data to a specific connection.

        Args:
            conn_id: Connection ID
            data: Data to send

        Raises:
            KeyError: If connection doesn't exist
            VaultProtocolError: If send fails
        """
        with self._conns_lock:
            conn = self._connections.get(conn_id)

        if not conn:
            raise KeyError(f"No such connection: {conn_id}")

        conn.send(data)

    def broadcast(self, data: bytes) -> None:
        """
        Broadcast data to all connected clients.

        Args:
            data: Data to broadcast
        """
        with self._conns_lock:
            conns = list(self._connections.items())

        for cid, conn in conns:
            try:
                conn.send(data)
            except Exception:
                logger.exception("Broadcast send failed for connection %d", cid)

    def get_connection_ids(self) -> list[int]:
        """Get list of all active connection IDs."""
        with self._conns_lock:
            return list(self._connections.keys())

    def get_connection_stats(self, conn_id: int) -> dict[str, t.Any]:
        """Get statistics for a specific connection."""
        with self._conns_lock:
            conn = self._connections.get(conn_id)

        if not conn:
            raise KeyError(f"No such connection: {conn_id}")

        return conn.get_stats()

    def close(self) -> None:
        """Shutdown the server gracefully."""
        logger.info("Shutting down server...")
        self._running.clear()

        # Close server socket
        with contextlib.suppress(Exception):
            self._server_sock.shutdown(socket.SHUT_RDWR)

        with contextlib.suppress(Exception):
            self._server_sock.close()

        # Wait for accept thread
        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=2.0)

        # Close all client connections
        with self._conns_lock:
            conns = list(self._connections.items())
            self._connections.clear()

        for _cid, conn in conns:
            with contextlib.suppress(Exception):
                conn.close()

        logger.info("Server shutdown complete")


class VaultTCPClient:
    """
    Simple client wrapper for VaultConnection.

    Usage:
        client = VaultTCPClient(server_ip="127.0.0.1", server_port=5004)
        client.connect()
        client.send(b"Hello")
        response = client.receive()
        client.close()

    Or with context manager:
        with VaultTCPClient(server_ip="127.0.0.1", server_port=5004) as client:
            response = client.send_and_receive(b"Hello")
    """

    def __init__(
        self,
        server_ip: str = "127.0.0.1",
        server_port: int = 5004,
        proto_name: str = "Noise_NN_25519_AESGCM_SHA512",
        max_message_size: int = 64 * 1024,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
        message_timeout: float = DEFAULT_MESSAGE_TIMEOUT,
        static_key: bytes | None = None,
        remote_static: bytes | None = None,
    ):
        """
        Initialize VaultTCPClient.

        Args:
            server_ip: Server IP address
            server_port: Server port
            proto_name: Noise protocol name
            max_message_size: Maximum message size
            handshake_timeout: Timeout for handshake
            message_timeout: Timeout for messages
            static_key: Optional static private key
            remote_static: Optional remote static public key
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.proto_name = proto_name
        self.max_message_size = max_message_size
        self.handshake_timeout = handshake_timeout
        self.message_timeout = message_timeout
        self.static_key = static_key
        self.remote_static = remote_static

        self._sock: socket.socket | None = None
        self._conn: VaultConnection | None = None

    def connect(self) -> None:
        """
        Connect to server and perform handshake.

        Raises:
            RuntimeError: If already connected
            VaultHandshakeError: If handshake fails
        """
        if self._sock:
            raise RuntimeError("Already connected")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.handshake_timeout)

        try:
            s.connect((self.server_ip, self.server_port))
        except Exception as e:
            s.close()
            raise VaultProtocolError(f"Connection failed: {e}") from e

        self._sock = s

        self._conn = VaultConnection(
            s,
            self.proto_name,
            is_initiator=True,
            max_message_size=self.max_message_size,
            handshake_timeout=self.handshake_timeout,
            message_timeout=self.message_timeout,
            static_key=self.static_key,
            remote_static=self.remote_static,
        )

        self._conn.do_handshake()
        logger.info("Client connected to %s:%d", self.server_ip, self.server_port)

    def send(self, data: bytes) -> None:
        """
        Send data to server.

        Args:
            data: Data to send

        Raises:
            RuntimeError: If not connected
            VaultProtocolError: If send fails
        """
        if not self._conn:
            raise RuntimeError("Not connected")
        self._conn.send(data)

    def receive(self) -> bytes:
        """
        Receive data from server.

        Returns:
            Received plaintext data

        Raises:
            RuntimeError: If not connected
            VaultProtocolError: If receive fails
        """
        if not self._conn:
            raise RuntimeError("Not connected")
        return self._conn.receive()

    def send_and_receive(self, data: bytes) -> bytes:
        """
        Send data and blockingly wait for one response.

        Args:
            data: Data to send

        Returns:
            Response from server
        """
        self.send(data)
        return self.receive()

    def get_stats(self) -> dict[str, t.Any]:
        """Get connection statistics."""
        if not self._conn:
            raise RuntimeError("Not connected")
        return self._conn.get_stats()

    def close(self) -> None:
        """Close the connection."""
        if self._conn:
            with contextlib.suppress(Exception):
                self._conn.close()
            self._conn = None

        if self._sock:
            with contextlib.suppress(Exception):
                self._sock.close()
            self._sock = None

        logger.info("Client closed")

    def __enter__(self) -> VaultTCPClient:
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: t.Any,
    ) -> t.Literal[False]:
        """Context manager exit."""
        self.close()
        return False


# Example usage
if __name__ == "__main__":
    import sys

    # Configure logging for demo
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    def on_message(conn_id: int, payload: bytes, conn: VaultConnection) -> None:
        """Echo server callback."""
        msg = payload.decode("utf-8", errors="replace")
        logger.info("Server received from conn %d: %s", conn_id, msg)

        # Echo back
        try:
            response = f"ECHO: {msg}".encode()
            conn.send(response)
        except Exception:
            logger.exception("Failed to echo to conn %d", conn_id)

    def on_connect(conn_id: int) -> None:
        logger.info("Client connected: %d", conn_id)

    def on_disconnect(conn_id: int) -> None:
        logger.info("Client disconnected: %d", conn_id)

    # Start server
    server = VaultTCPServer(listen_ip="127.0.0.1", listen_port=5004)
    server.on_message = on_message
    server.on_connect = on_connect
    server.on_disconnect = on_disconnect
    server.start()

    logger.info("Echo server running. Press Ctrl+C to stop.")
    logger.info("Testing with client...")

    # Test with client
    try:
        with VaultTCPClient(server_ip="127.0.0.1", server_port=5004) as client:
            response = client.send_and_receive(b"Hello, Server!")
            logger.info("Client received: %s", response.decode("utf-8"))

            # Show stats
            stats = client.get_stats()
            logger.info("Client stats: %s", stats)

    except Exception as e:
        logger.exception("Client error: %s", e)

    # Keep server running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.close()
        sys.exit(0)
