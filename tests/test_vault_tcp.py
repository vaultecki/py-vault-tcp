# Copyright [2025] [ecki]
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import socket
import time
from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vault_tcp import (
    VaultConnection,
    VaultConnectionClosed,
    VaultHandshakeError,
    VaultProtocolError,
    VaultTCPClient,
    VaultTCPServer,
)


def _generate_static_key() -> bytes:
    key = X25519PrivateKey.generate()
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_bytes(private_key: bytes) -> bytes:
    public = X25519PrivateKey.from_private_bytes(private_key).public_key()
    return public.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
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


def test_tcp_nodelay_is_set_on_both_sides(server: VaultTCPServer) -> None:
    with _client(server) as client:
        deadline = time.time() + 2.0
        while not server.get_connection_ids() and time.time() < deadline:
            time.sleep(0.02)

        assert client._sock is not None
        assert client._sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0

        conn_id = server.get_connection_ids()[0]
        server_sock = server._connections[conn_id].sock
        assert server_sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0


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


def test_connection_receive_timeout_budget_is_not_doubled() -> None:
    """Header and payload reads must share one timeout budget, not each get
    a full message_timeout (which would let one receive() call block for up
    to 2x message_timeout)."""
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True)
        responder = VaultConnection(
            sock2, "Noise_NN_25519_AESGCM_SHA512", is_initiator=False, message_timeout=0.3
        )
        _do_handshake_pair(initiator, responder)
        # Nothing is ever sent, so this always times out; only the elapsed
        # time is under test here.

        start = time.monotonic()
        with pytest.raises(TimeoutError):
            responder.receive()
        elapsed = time.monotonic() - start

        assert elapsed < 0.6  # well under 2x message_timeout (0.6s)
    finally:
        sock1.close()
        sock2.close()


def test_connection_payload_timeout_after_header_closes_connection() -> None:
    """A timeout while waiting for the payload must not be treated as a safe,
    retryable idle timeout even if zero payload bytes arrived: the header was
    already consumed, so retrying would misread the stream."""
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True)
        responder = VaultConnection(
            sock2, "Noise_NN_25519_AESGCM_SHA512", is_initiator=False, message_timeout=0.2
        )
        _do_handshake_pair(initiator, responder)

        sock1.sendall((100).to_bytes(4, "big"))  # full header, then never send the payload

        with pytest.raises(VaultProtocolError, match="desynchronized"):
            responder.receive()
        assert responder._closed is True
    finally:
        sock1.close()
        sock2.close()


def test_idle_timeout_disconnects_inactive_client(server: VaultTCPServer) -> None:
    server.idle_timeout = 0.3
    server.message_timeout = 2.0  # much larger than idle_timeout on purpose

    disconnected_ids: list[int] = []
    server.on_disconnect = disconnected_ids.append

    with _client(server):
        deadline = time.time() + 2.0
        while not disconnected_ids and time.time() < deadline:
            time.sleep(0.02)

    assert len(disconnected_ids) == 1


def test_authenticated_xx_handshake_roundtrip() -> None:
    """XX authenticates both sides via their static keys (exchanged, encrypted,
    during the handshake itself - unlike NN, which is fully anonymous)."""
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(
            sock1,
            "Noise_XX_25519_AESGCM_SHA512",
            is_initiator=True,
            static_key=_generate_static_key(),
        )
        responder = VaultConnection(
            sock2,
            "Noise_XX_25519_AESGCM_SHA512",
            is_initiator=False,
            static_key=_generate_static_key(),
        )
        _do_handshake_pair(initiator, responder)

        initiator.send(b"authenticated hello")
        assert responder.receive() == b"authenticated hello"
    finally:
        sock1.close()
        sock2.close()


def test_get_remote_static_none_for_nn() -> None:
    """NN never exchanges a static key, so there's nothing to authenticate."""
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True)
        responder = VaultConnection(sock2, "Noise_NN_25519_AESGCM_SHA512", is_initiator=False)
        _do_handshake_pair(initiator, responder)

        assert initiator.get_remote_static() is None
        assert responder.get_remote_static() is None
    finally:
        sock1.close()
        sock2.close()


def test_get_remote_static_returns_peer_public_key_for_xx() -> None:
    """XX exchanges static keys, so each side should see the other's public key."""
    initiator_key = _generate_static_key()
    responder_key = _generate_static_key()

    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(
            sock1, "Noise_XX_25519_AESGCM_SHA512", is_initiator=True, static_key=initiator_key
        )
        responder = VaultConnection(
            sock2, "Noise_XX_25519_AESGCM_SHA512", is_initiator=False, static_key=responder_key
        )
        _do_handshake_pair(initiator, responder)

        assert initiator.get_remote_static() == _public_bytes(responder_key)
        assert responder.get_remote_static() == _public_bytes(initiator_key)
    finally:
        sock1.close()
        sock2.close()


def test_server_constructor_does_not_bind_port() -> None:
    """Constructing a server must not reserve the port - only start() should."""
    port = _free_port()
    srv1 = VaultTCPServer(listen_ip="127.0.0.1", listen_port=port)
    srv2 = VaultTCPServer(listen_ip="127.0.0.1", listen_port=port)  # must not raise
    del srv1, srv2


def test_client_allowlist_accepts_known_key_rejects_unknown() -> None:
    allowed_key = _generate_static_key()
    other_key = _generate_static_key()

    srv = VaultTCPServer(
        listen_ip="127.0.0.1",
        listen_port=_free_port(),
        proto_name="Noise_XX_25519_AESGCM_SHA512",
        static_key=_generate_static_key(),
        client_allowlist={_public_bytes(allowed_key)},
        handshake_timeout=2.0,
        message_timeout=2.0,
        idle_timeout=0,
    )
    srv.start()
    try:
        connected_ids: list[int] = []
        srv.on_connect = connected_ids.append

        with _client(
            srv, proto_name="Noise_XX_25519_AESGCM_SHA512", static_key=allowed_key
        ) as client:
            deadline = time.time() + 2.0
            while not connected_ids and time.time() < deadline:
                time.sleep(0.02)
            assert len(connected_ids) == 1
            client.send(b"hi")  # connection should be usable

        rejected = VaultTCPClient(
            server_ip=srv.listen_ip,
            server_port=srv.listen_port,
            proto_name="Noise_XX_25519_AESGCM_SHA512",
            static_key=other_key,
            handshake_timeout=2.0,
            message_timeout=2.0,
        )
        rejected.connect()
        try:
            # Server closes the connection after rejecting the allowlist check;
            # the client observes this as a closed connection on next I/O.
            with pytest.raises((VaultProtocolError, VaultConnectionClosed, OSError)):
                rejected.send_and_receive(b"hi")
        finally:
            rejected.close()

        assert len(connected_ids) == 1
    finally:
        srv.close()


def test_handshake_timeout_raises_timeout_error() -> None:
    """If the peer never responds, do_handshake() must time out rather than
    block forever."""
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(
            sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True, handshake_timeout=0.2
        )
        # Nothing reads sock2's end or responds, so initiator's read after
        # its first write will time out.
        with pytest.raises(TimeoutError):
            initiator.do_handshake()
    finally:
        sock1.close()
        sock2.close()


def test_handshake_proto_mismatch_raises_handshake_error() -> None:
    """Mismatched Noise patterns produce handshake messages the other side
    can't parse - this must surface as VaultHandshakeError, not hang or
    crash with a raw library exception."""
    sock1, sock2 = socket.socketpair()
    try:
        initiator = VaultConnection(
            sock1, "Noise_NN_25519_AESGCM_SHA512", is_initiator=True, handshake_timeout=2.0
        )
        responder = VaultConnection(
            sock2, "Noise_XX_25519_AESGCM_SHA512", is_initiator=False, handshake_timeout=2.0
        )

        with pytest.raises((VaultHandshakeError, TimeoutError)):
            _do_handshake_pair(initiator, responder)
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
