# Bitcoin Rust Node

A Bitcoin full node implementation in Rust, built following a phased approach starting with testnet support.

## Current Status

**Phase 1.1 Complete**: Project initialization with basic structure and configuration.

## Project Structure

```
bitcoin-rust/
├── Cargo.toml
├── src/
│   ├── main.rs              # Entry point
│   ├── config.rs            # Network configuration
│   ├── network/             # P2P networking (Phase 1.2)
│   ├── blockchain/          # Block storage and validation (Phase 2)
│   ├── mempool/             # Transaction pool (Phase 4)
│   ├── consensus/           # Consensus rules (Phase 3)
│   ├── storage/             # Database layer (Phase 2)
│   └── rpc/                 # Optional RPC server (Phase 5)
└── README.md
```

## Dependencies

- `bitcoin` (v0.31+): Core Bitcoin types and serialization
- `secp256k1` (v0.28+): Cryptographic operations
- `tokio`: Async runtime for networking
- `rocksdb`: Persistent storage
- `tracing`: Logging and diagnostics

## Running the Node

```bash
# Build the project
cargo build

# Run with testnet (default)
cargo run

# Run with custom log level
RUST_LOG=debug cargo run
```

## Configuration

The node supports both testnet and mainnet configurations:

- **Testnet** (default): Port 18333, data directory `./data/testnet`
- **Mainnet**: Port 8333, data directory `./data/mainnet`

Configuration can be modified in `src/config.rs` or loaded from environment variables (future enhancement).

## Implementation Phases

1. **Phase 1**: Foundation & P2P Networking
2. **Phase 2**: Blockchain Synchronization
3. **Phase 3**: Block & Transaction Validation
4. **Phase 4**: Mempool & Transaction Relay
5. **Phase 5**: Advanced Features & Mainnet

See `PLAN.md` for detailed implementation roadmap.
