# Vault TCP

TCP client/server for exchanging length-prefixed, Noise Protocol-encrypted
messages, built on [noiseprotocol](https://github.com/plizonczyk/noiseprotocol).

## Requirements

- Python 3.10+
- `noiseprotocol>=0.3.1`
- `cryptography>=41.0.0`

## Installation

```bash
git clone <repository-url>
cd vault-tcp

pip install -e .            # runtime only
pip install -e ".[dev]"     # + ruff, mypy, pytest, pre-commit
```

## Quick start

### Server

```python
from vault_tcp import VaultTCPServer, VaultConnection

def handle_message(conn_id: int, data: bytes, conn: VaultConnection) -> None:
    conn.send(b"ECHO: " + data)

server = VaultTCPServer(listen_ip="0.0.0.0", listen_port=5004)
server.on_message = handle_message
server.start()  # non-blocking, spawns its own threads

# ...
server.close()
```

> **This default (`Noise_NN_...`) is unauthenticated** - encrypted, but
> anyone can complete a handshake with the server, and an active
> man-in-the-middle can too. See "Noise protocol / pattern selection" below
> before using this for anything where knowing *who* you're talking to
> matters.

### Client

```python
from vault_tcp import VaultTCPClient

with VaultTCPClient(server_ip="127.0.0.1", server_port=5004) as client:
    response = client.send_and_receive(b"Hello, Server!")
```

## How it works

- Messages are framed as a 4-byte big-endian length prefix followed by the
  Noise ciphertext.
- `VaultTCPServer` runs an accept loop and spawns one thread per connection.
  Callbacks (`on_connect`, `on_message`, `on_disconnect`) run on that
  connection's thread.
- `VaultConnection.send()` is safe to call from multiple threads.
  `VaultConnection.receive()` is not - use it from a single thread per
  connection (which is how the server already uses it).
- A connection that hits an encryption, decryption, or framing error closes
  itself. The Noise cipher's nonce counter advances on every
  encrypt/decrypt call, so a message that fails to fully send or a stream
  read that fails mid-frame leaves the two sides out of sync; the
  connection is not safe to reuse afterwards.

## Noise protocol / pattern selection

Default: `Noise_NN_25519_AESGCM_SHA512` - X25519 key exchange, AES-GCM,
SHA-512, and the **NN** pattern, meaning neither side authenticates the
other. The transport is encrypted, but **NN is vulnerable to an active
man-in-the-middle**: nothing in the handshake ties the connection to a known
identity, so anyone (including an attacker positioned on the network path)
can complete a handshake with the server, and the server has no way to tell
its intended client from an impostor. Only use the default for
prototyping, or when the network path is already trusted by some other
means. For anything where knowing *who* you're talking to matters, use an
authenticated pattern.

For authentication, pass a different `proto_name` and static keys:

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

private_key = X25519PrivateKey.generate()
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)

server = VaultTCPServer(
    proto_name="Noise_XX_25519_AESGCM_SHA512",
    static_key=private_bytes,
)
client = VaultTCPClient(
    proto_name="Noise_XX_25519_AESGCM_SHA512",
    static_key=private_bytes,
)
```

Pattern letters (see the [Noise spec](http://www.noiseprotocol.org/noise.html#handshake-patterns)):

| Pattern | Meaning |
|---|---|
| NN | No authentication (default) - vulnerable to active MITM |
| XX | Both sides authenticate, static keys exchanged during handshake |
| NK | Client verifies a known server static key |
| IK | Client sends its static key immediately, knows the server's in advance |

### Restricting which clients may connect

With a pattern that authenticates the client (XX, IK, ...), pass
`client_allowlist` to `VaultTCPServer` to reject any client whose static
public key isn't in the set - otherwise an authenticated pattern only
proves the client holds *some* consistent key pair, not that it's one you
recognize:

```python
allowed_clients = {client_public_key_bytes, ...}  # 32 raw bytes each, X25519

server = VaultTCPServer(
    proto_name="Noise_XX_25519_AESGCM_SHA512",
    static_key=server_private_bytes,
    client_allowlist=allowed_clients,
)
```

A rejected client completes the (cryptographic) handshake but the
connection is then immediately closed server-side, before it is registered
or any callback fires. `VaultConnection.get_remote_static()` returns the
peer's static public key after handshake (or `None` for patterns that don't
exchange one, e.g. NN) if you need to inspect or authenticate it yourself
instead.

## API

### `VaultTCPServer`

```python
VaultTCPServer(
    listen_ip: str = "0.0.0.0",
    listen_port: int = 5004,
    proto_name: str = "Noise_NN_25519_AESGCM_SHA512",
    max_message_size: int = 64 * 1024,
    handshake_timeout: float = 10.0,
    message_timeout: float = 30.0,
    idle_timeout: float = 300.0,  # 0 disables idle disconnection
    static_key: bytes | None = None,
    client_allowlist: Collection[bytes] | None = None,
)
```

- `start()` - binds the socket, starts listening, and starts the accept
  loop (nothing is bound until this is called)
- `close()` - stop the accept loop and disconnect all clients
- `send_to(conn_id, data)`, `broadcast(data)`
- `get_connection_ids() -> list[int]`
- `get_connection_stats(conn_id) -> dict`
- callbacks: `on_connect(conn_id)`, `on_message(conn_id, data, conn)`,
  `on_disconnect(conn_id)` - set before calling `start()`
- `static_key` / `client_allowlist` - see "Restricting which clients may
  connect" above

### `VaultTCPClient`

```python
VaultTCPClient(
    server_ip: str = "127.0.0.1",
    server_port: int = 5004,
    proto_name: str = "Noise_NN_25519_AESGCM_SHA512",
    max_message_size: int = 64 * 1024,
    handshake_timeout: float = 10.0,
    message_timeout: float = 30.0,
    static_key: bytes | None = None,
    remote_static: bytes | None = None,
)
```

- `connect()` / `close()`, or use as a context manager (calls `connect()`
  on enter)
- `send(data)`, `receive() -> bytes`, `send_and_receive(data) -> bytes`
- `get_stats() -> dict`

### `VaultConnection`

Wraps one handshaked socket. Used internally by both of the above;
construct directly only if you need to manage the socket yourself.

- `do_handshake()`, `send(plaintext)`, `receive() -> bytes`, `close()`,
  `get_stats() -> dict`

## Errors

```python
from vault_tcp import VaultProtocolError, VaultHandshakeError, VaultConnectionClosed

try:
    with VaultTCPClient() as client:
        client.send(b"data")
except VaultHandshakeError:
    ...  # handshake didn't complete
except VaultConnectionClosed:
    ...  # peer closed the connection
except VaultProtocolError:
    ...  # encryption/decryption/framing failure; connection is closed
except TimeoutError:
    ...  # no data arrived in time; connection may still be usable
```

## Logging

Uses the standard `logging` module under the `vault_tcp` logger name.

```python
import logging
logging.getLogger("vault_tcp").setLevel(logging.DEBUG)
```

## Limitations / things to know before using this for anything real

- Default pattern (NN) is unauthenticated and vulnerable to an active
  man-in-the-middle - use XX/NK/IK if you need to verify who you're talking
  to, plus `client_allowlist` on the server if you also need to restrict
  which authenticated clients are accepted.
- No built-in rate limiting or connection limits.
- One thread per connection; not tested at high connection counts.
- `max_message_size` bounds a single message but there's no application-level
  flow control beyond TCP's own backpressure.
- Not independently security-audited.

## Development

```bash
pip install -e ".[dev]"

ruff check .        # lint
ruff format .       # format
mypy vault_tcp.py   # type-check
pytest              # tests
```

```bash
pre-commit install  # run the above automatically before each commit
```

CI (`.github/workflows/ci.yml`) runs the same checks on Python 3.10-3.13.

## Troubleshooting

- **Handshake fails**: both sides must use the same `proto_name`.
- **Connection closes unexpectedly**: check `idle_timeout`/`message_timeout`
  values, and whether the peer is closing its side.
- **`VaultProtocolError` after previously working fine**: the connection
  hit an error and closed itself (see "How it works" above) - open a new one.

## License

Apache-2.0, Copyright 2025 ecki. See [LICENSE](LICENSE).

## Credits

Built on [noiseprotocol](https://github.com/plizonczyk/noiseprotocol),
an implementation of the [Noise Protocol Framework](http://www.noiseprotocol.org/).
