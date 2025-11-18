# Vault TCP - Secure TCP Communication with Noise Protocol

A Python implementation of secure TCP communication using the [Noise Protocol Framework](http://www.noiseprotocol.org/).

## Features

- 🔒 **Strong Encryption**: Uses Noise protocol with X25519, AESGCM, and SHA512
- 🔄 **Multi-client Support**: Threaded server handles multiple concurrent connections
- 📦 **Length-Prefixed Framing**: Robust message framing with 4-byte headers
- ⏱️ **Timeout Management**: Configurable timeouts for handshake, messages, and idle connections
- 📊 **Statistics**: Built-in connection statistics and monitoring
- 🧵 **Thread-Safe**: Send operations are thread-safe
- 🎯 **Context Manager Support**: Clean resource management with `with` statements
- 🛡️ **Robust Error Handling**: Comprehensive error handling and logging
- 📝 **Type Hints**: Full type annotations for better IDE support

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd vault-tcp

# Install dependencies
pip install -r requirements.txt
```

### Requirements

- Python 3.8 or higher
- `noiseprotocol>=0.3.1`
- `cryptography>=41.0.0`

## Quick Start

### Echo Server Example

```python
from vault_tcp import VaultTCPServer, VaultConnection
import logging

logging.basicConfig(level=logging.INFO)

def handle_message(conn_id: int, data: bytes, conn: VaultConnection):
    """Echo back received messages"""
    print(f"Received from {conn_id}: {data.decode()}")
    conn.send(b"ECHO: " + data)

# Create and start server
server = VaultTCPServer(listen_ip="0.0.0.0", listen_port=5004)
server.on_message = handle_message
server.start()

print("Server running on port 5004...")
# Keep server running
try:
    while True:
        import time
        time.sleep(1)
except KeyboardInterrupt:
    server.close()
```

### Client Example

```python
from vault_tcp import VaultTCPClient

# Using context manager (recommended)
with VaultTCPClient(server_ip="127.0.0.1", server_port=5004) as client:
    response = client.send_and_receive(b"Hello, Server!")
    print(f"Server responded: {response.decode()}")

# Manual connection management
client = VaultTCPClient(server_ip="127.0.0.1", server_port=5004)
client.connect()
client.send(b"Hello")
response = client.receive()
client.close()
```

## API Reference

### VaultTCPServer

Multi-client server with threaded connection handling.

#### Constructor

```python
VaultTCPServer(
    listen_ip: str = "0.0.0.0",
    listen_port: int = 5004,
    proto_name: str = "Noise_NN_25519_AESGCM_SHA512",
    max_message_size: int = 64 * 1024,
    handshake_timeout: float = 10.0,
    message_timeout: float = 30.0,
    idle_timeout: float = 300.0
)
```

**Parameters:**
- `listen_ip`: IP address to bind to (default: "0.0.0.0")
- `listen_port`: Port to listen on (default: 5004)
- `proto_name`: Noise protocol name (default: "Noise_NN_25519_AESGCM_SHA512")
- `max_message_size`: Maximum plaintext message size in bytes (default: 64KB)
- `handshake_timeout`: Timeout for handshake operations in seconds (default: 10s)
- `message_timeout`: Timeout for message operations in seconds (default: 30s)
- `idle_timeout`: Timeout for idle connections in seconds, 0 to disable (default: 300s)

#### Methods

- **`start()`**: Start the server (non-blocking)
- **`send_to(conn_id: int, data: bytes)`**: Send data to specific connection
- **`broadcast(data: bytes)`**: Send data to all connected clients
- **`get_connection_ids() -> List[int]`**: Get list of active connection IDs
- **`get_connection_stats(conn_id: int) -> dict`**: Get statistics for a connection
- **`close()`**: Shutdown server gracefully

#### Callbacks

Set these before calling `start()`:

```python
server.on_message = lambda conn_id, data, conn: ...
server.on_connect = lambda conn_id: ...
server.on_disconnect = lambda conn_id: ...
```

- **`on_message(conn_id: int, data: bytes, conn: VaultConnection)`**: Called when message received
- **`on_connect(conn_id: int)`**: Called when client connects
- **`on_disconnect(conn_id: int)`**: Called when client disconnects

### VaultTCPClient

Client wrapper for connecting to VaultTCPServer.

#### Constructor

```python
VaultTCPClient(
    server_ip: str = "127.0.0.1",
    server_port: int = 5004,
    proto_name: str = "Noise_NN_25519_AESGCM_SHA512",
    max_message_size: int = 64 * 1024,
    handshake_timeout: float = 10.0,
    message_timeout: float = 30.0,
    static_key: Optional[bytes] = None,
    remote_static: Optional[bytes] = None
)
```

#### Methods

- **`connect()`**: Connect to server and perform handshake
- **`send(data: bytes)`**: Send data to server
- **`receive() -> bytes`**: Receive data from server (blocking)
- **`send_and_receive(data: bytes) -> bytes`**: Send and wait for response
- **`get_stats() -> dict`**: Get connection statistics
- **`close()`**: Close connection

#### Context Manager Support

```python
with VaultTCPClient(server_ip="127.0.0.1") as client:
    response = client.send_and_receive(b"Hello")
```

### VaultConnection

Low-level connection wrapper (typically not used directly).

#### Methods

- **`do_handshake()`**: Perform Noise protocol handshake
- **`send(plaintext: bytes)`**: Encrypt and send message (thread-safe)
- **`receive() -> bytes`**: Receive and decrypt message
- **`get_stats() -> dict`**: Get connection statistics
- **`close()`**: Close connection

## Noise Protocol

By default, uses **Noise_NN_25519_AESGCM_SHA512**:
- **NN**: No static keys (anonymous)
- **25519**: X25519 for key exchange
- **AESGCM**: AES-GCM for encryption
- **SHA512**: SHA-512 for hashing

### Other Supported Patterns

You can use different Noise patterns by changing `proto_name`:

```python
# With static keys for authentication
server = VaultTCPServer(proto_name="Noise_XX_25519_AESGCM_SHA512")

# With pre-shared key
server = VaultTCPServer(proto_name="Noise_NK_25519_AESGCM_SHA512")
```

Common patterns:
- **NN**: Anonymous (no authentication)
- **XX**: Mutual authentication with key exchange
- **NK**: Server authentication
- **IK**: Client knows server's static key

See [Noise Protocol Patterns](http://www.noiseprotocol.org/noise.html#patterns) for details.

## Advanced Usage

### Custom Callbacks with State

```python
class ChatServer:
    def __init__(self):
        self.clients = {}
        self.server = VaultTCPServer()
        self.server.on_message = self.handle_message
        self.server.on_connect = self.handle_connect
        self.server.on_disconnect = self.handle_disconnect
    
    def handle_connect(self, conn_id: int):
        self.clients[conn_id] = {"joined": time.time()}
        print(f"Client {conn_id} joined")
    
    def handle_message(self, conn_id: int, data: bytes, conn: VaultConnection):
        message = data.decode('utf-8')
        print(f"[{conn_id}]: {message}")
        
        # Broadcast to all other clients
        for cid in self.clients:
            if cid != conn_id:
                try:
                    self.server.send_to(cid, f"[{conn_id}]: {message}".encode())
                except Exception as e:
                    print(f"Failed to send to {cid}: {e}")
    
    def handle_disconnect(self, conn_id: int):
        if conn_id in self.clients:
            del self.clients[conn_id]
        print(f"Client {conn_id} left")
    
    def start(self):
        self.server.start()

# Usage
chat = ChatServer()
chat.start()
```

### Connection Statistics

```python
# Server-side
stats = server.get_connection_stats(conn_id)
print(f"Connection {conn_id}:")
print(f"  Bytes sent: {stats['bytes_sent']}")
print(f"  Bytes received: {stats['bytes_received']}")
print(f"  Messages sent: {stats['messages_sent']}")
print(f"  Messages received: {stats['messages_received']}")
print(f"  Uptime: {stats['uptime_seconds']:.1f}s")

# Client-side
stats = client.get_stats()
```

### Using Static Keys for Authentication

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Generate static keypair
private_key = X25519PrivateKey.generate()
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

# Server with static key
server = VaultTCPServer(
    proto_name="Noise_XX_25519_AESGCM_SHA512"
)

# Client with static key
client = VaultTCPClient(
    proto_name="Noise_XX_25519_AESGCM_SHA512",
    static_key=private_bytes
)
```

## Error Handling

The library uses specific exception types:

```python
from vault_tcp import (
    VaultProtocolError,      # Base protocol error
    VaultHandshakeError,     # Handshake failed
    VaultConnectionClosed    # Connection closed unexpectedly
)

try:
    with VaultTCPClient() as client:
        client.send(b"data")
except VaultHandshakeError as e:
    print(f"Handshake failed: {e}")
except VaultConnectionClosed as e:
    print(f"Connection closed: {e}")
except VaultProtocolError as e:
    print(f"Protocol error: {e}")
except TimeoutError as e:
    print(f"Operation timed out: {e}")
```

## Logging

The library uses Python's standard `logging` module:

```python
import logging

# Configure logging level
logging.getLogger("vault_tcp").setLevel(logging.DEBUG)

# Or configure all logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
```

## Security Considerations

1. **Noise Protocol**: Provides forward secrecy and strong encryption
2. **Message Size Limits**: Default 64KB prevents memory exhaustion attacks
3. **Timeouts**: Prevent resource exhaustion from slow/stalled connections
4. **Idle Detection**: Automatically closes inactive connections
5. **No Authentication**: Default NN pattern is anonymous - use XX/IK patterns for authentication

### Production Recommendations

- Use authenticated patterns (XX, IK) instead of anonymous (NN)
- Implement rate limiting for your use case
- Monitor connection statistics for anomalies
- Use TLS for additional transport security if needed
- Validate message contents after decryption
- Run behind a firewall or reverse proxy

## Testing

Run the included example:

```bash
python vault_tcp.py
```

This starts an echo server and tests it with a client.

## Performance

Typical performance on modern hardware:
- **Throughput**: ~100-200 MB/s per connection
- **Latency**: <1ms for small messages on localhost
- **Concurrent Connections**: Hundreds to thousands (OS dependent)

The server uses one thread per connection, suitable for moderate connection counts. For very high connection counts, consider implementing an async version.

## Troubleshooting

### "Handshake failed" errors

- Check that both sides use the same `proto_name`
- Verify network connectivity
- Check firewall rules
- Ensure sufficient timeout values

### "Connection closed" errors

- Check idle timeout settings
- Verify both sides are properly closing connections
- Check network stability

### High CPU usage

- Reduce number of concurrent connections
- Increase message batching
- Check for busy-wait loops in callbacks

### Memory issues

- Reduce `max_message_size` if messages are large
- Implement connection limits
- Monitor for connection leaks (forgotten `close()`)

## License

- Copyright [2025] [ecki]
- SPDX-License-Identifier: Apache-2.0


## Contributing

[Add contributing guidelines here]

## Credits

Built with:
- [noiseprotocol](https://github.com/plizonczyk/noiseprotocol) - Python implementation of Noise Protocol
- [Noise Protocol Framework](http://www.noiseprotocol.org/) - By Trevor Perrin

## Changelog

### Version 2.0 (Current)
- Complete rewrite with robust error handling
- Added context manager support
- Improved handshake logic
- Added connection statistics
- Added idle timeout detection
- Improved logging and type hints
- Better thread safety
- Graceful shutdown

### Version 1.0 (Original)
- Initial implementation
- Basic Noise protocol support
- Multi-threaded server
