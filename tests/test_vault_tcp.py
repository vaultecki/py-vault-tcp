# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import socket
import time
from collections.abc import Iterator

import pytest

from vault_tcp import (
    VaultConnection,
    VaultConnectionClosed,
    VaultProtocolError,
    VaultTCPClient,
    VaultTCPServer,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def server() -> Iterator[VaultTCPServer]:
    srv = VaultTCPServer(
        listen_ip="127.0.0.1",
        listen_port=_free_port(),
        handshake_timeout=2.0,
        message_timeout=2.0,
        idle_timeout=0,
    )
    srv.start()
    try:
        yield srv
    finally:
        srv.close()


def _client(server: VaultTCPServer, **kwargs: object) -> VaultTCPClient:
    return VaultTCPClient(
        server_ip=server.listen_ip,
        server_port=server.listen_port,
        handshake_timeout=2.0,
        message_timeout=2.0,
        **kwargs,  # type: ignore[arg-type]
    )


def test_handshake_and_echo_roundtrip(server: VaultTCPServer) -> None:
    def echo(conn_id: int, data: bytes, conn: VaultConnection) -> None:
        conn.send(b"ECHO: " + data)

    server.on_message = echo

    with _client(server) as client:
        response = client.send_and_receive(b"hello")

    assert response == b"ECHO: hello"


def test_multiple_clients_get_distinct_ids(server: VaultTCPServer) -> None:
    connected_ids: list[int] = []
    server.on_connect = connected_ids.append

    with _client(server) as c1, _client(server) as c2:
        # Give the server a moment to register both handshakes.
        deadline = time.time() + 2.0
        while len(connected_ids) < 2 and time.time() < deadline:
            time.sleep(0.02)

        assert len(connected_ids) == 2
        assert len(set(connected_ids)) == 2
        assert sorted(server.get_connection_ids()) == sorted(connected_ids)
        del c1, c2


def test_on_disconnect_called_after_client_closes(server: VaultTCPServer) -> None:
    disconnected_ids: list[int] = []
    server.on_disconnect = disconnected_ids.append

    client = _client(server)
    client.connect()
    client.close()

    deadline = time.time() + 2.0
    while not disconnected_ids and time.time() < deadline:
        time.sleep(0.02)

    assert len(disconnected_ids) == 1


def test_broadcast_reaches_all_clients(server: VaultTCPServer) -> None:
    with _client(server) as c1, _client(server) as c2:
        deadline = time.time() + 2.0
        while len(server.get_connection_ids()) < 2 and time.time() < deadline:
            time.sleep(0.02)

        server.broadcast(b"hi everyone")

        assert c1.receive() == b"hi everyone"
        assert c2.receive() == b"hi everyone"


def test_send_to_unknown_connection_raises_key_error(server: VaultTCPServer) -> None:
    with pytest.raises(KeyError):
        server.send_to(999, b"data")


def test_get_connection_stats_unknown_raises_key_error(server: VaultTCPServer) -> None:
    with pytest.raises(KeyError):
        server.get_connection_stats(999)


def test_client_stats_track_sent_and_received_messages(server: VaultTCPServer) -> None:
    def echo(conn_id: int, data: bytes, conn: VaultConnection) -> None:
        conn.send(data)

    server.on_message = echo

    with _client(server) as client:
        client.send_and_receive(b"abc")
        stats = client.get_stats()

    assert stats["messages_sent"] == 1
    assert stats["messages_received"] == 1
    assert stats["handshake_complete"] is True
    assert stats["closed"] is False


def test_client_send_without_connect_raises_runtime_error() -> None:
    client = VaultTCPClient(server_ip="127.0.0.1", server_port=1)
    with pytest.raises(RuntimeError):
        client.send(b"data")


def test_client_receive_without_connect_raises_runtime_error() -> None:
    client = VaultTCPClient(server_ip="127.0.0.1", server_port=1)
    with pytest.raises(RuntimeError):
        client.receive()


def test_connection_send_before_handshake_raises_protocol_error() -> None:
    sock1, sock2 = socket.socketpair()
    try:
        conn = VaultConnection(sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True)
        with pytest.raises(VaultProtocolError):
            conn.send(b"data")
    finally:
        sock1.close()
        sock2.close()


def test_connection_send_wrong_type_raises_type_error() -> None:
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True)
        responder = VaultConnection(sock2, "Noise_NN_25519_AESGCM_SHA512", is_initiator=False)
        _do_handshake_pair(initiator, responder)

        with pytest.raises(TypeError):
            initiator.send("not bytes")  # type: ignore[arg-type]
    finally:
        sock1.close()
        sock2.close()


def test_connection_send_exceeding_max_size_raises_value_error() -> None:
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(
            sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True, max_message_size=8
        )
        responder = VaultConnection(
            sock2, "Noise_NN_25519_AESGCM_SHA512", is_initiator=False, max_message_size=8
        )
        _do_handshake_pair(initiator, responder)

        with pytest.raises(ValueError, match="exceeds maximum"):
            initiator.send(b"way too long for the limit")
    finally:
        sock1.close()
        sock2.close()


def test_connection_receive_after_close_raises_connection_closed() -> None:
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True)
        responder = VaultConnection(sock2, "Noise_NN_25519_AESGCM_SHA512", is_initiator=False)
        _do_handshake_pair(initiator, responder)

        sock1.close()
        with pytest.raises(VaultConnectionClosed):
            responder.receive()
        assert responder._closed is True
    finally:
        sock2.close()


def test_connection_send_failure_closes_connection() -> None:
    """A failed send leaves the Noise nonce counter advanced but the message
    never delivered, desynchronizing both sides - the connection must not be
    reusable afterwards."""
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True)
        responder = VaultConnection(sock2, "Noise_NN_25519_AESGCM_SHA512", is_initiator=False)
        _do_handshake_pair(initiator, responder)

        sock1.close()  # sendall() on a closed socket raises
        with pytest.raises(VaultProtocolError):
            initiator.send(b"data")
        assert initiator._closed is True

        with pytest.raises(VaultProtocolError, match="closed"):
            initiator.send(b"data again")
    finally:
        sock2.close()


def test_connection_decrypt_failure_closes_connection() -> None:
    """Garbage ciphertext (tampering, or a desynced nonce) must not leave a
    connection that looks reusable."""
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True)
        responder = VaultConnection(sock2, "Noise_NN_25519_AESGCM_SHA512", is_initiator=False)
        _do_handshake_pair(initiator, responder)

        garbage = b"\x00" * 32
        sock1.sendall(len(garbage).to_bytes(4, "big") + garbage)

        with pytest.raises(VaultProtocolError, match="Decryption failed"):
            responder.receive()
        assert responder._closed is True
    finally:
        sock1.close()
        sock2.close()


def test_connection_partial_frame_timeout_closes_connection() -> None:
    """A timeout after only part of a frame's bytes were consumed leaves the
    stream byte-misaligned (the consumed bytes can't be put back), so it must
    raise VaultProtocolError and close rather than a retry-safe TimeoutError."""
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True)
        responder = VaultConnection(
            sock2, "Noise_NN_25519_AESGCM_SHA512", is_initiator=False, message_timeout=0.2
        )
        _do_handshake_pair(initiator, responder)

        sock1.sendall(b"\x00\x00")  # half of the 4-byte length header, then stall

        with pytest.raises(VaultProtocolError, match="desynchronized"):
            responder.receive()
        assert responder._closed is True
    finally:
        sock1.close()
        sock2.close()


def test_connection_context_manager_closes_socket() -> None:
    sock1, sock2 = socket.socketpair()
    try:
        with VaultConnection(sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True) as conn:
            assert conn._closed is False
        assert conn._closed is True
    finally:
        sock2.close()


def _do_handshake_pair(initiator: VaultConnection, responder: VaultConnection) -> None:
    """Run both sides of a handshake in lockstep over an in-process socketpair."""
    import threading

    errors: list[Exception] = []

    def run(conn: VaultConnection) -> None:
        try:
            conn.do_handshake()
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=run, args=(initiator,))
    t2 = threading.Thread(target=run, args=(responder,))
    t1.start()
    t2.start()
    t1.join(timeout=2.0)
    t2.join(timeout=2.0)

    if errors:
        raise errors[0]
