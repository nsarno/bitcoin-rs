# Bitcoin Rust Node

A Bitcoin full node implementation in Rust, built following a phased approach starting with testnet support.

## Current Status

**Phase 1 Complete**: Foundation & P2P Networking

- ✅ Project initialization with basic structure and configuration
- ✅ Bitcoin message serialization/deserialization
- ✅ Version handshake (`version`, `verack`) implementation
- ✅ Keepalive mechanism (`ping`, `pong`) with comprehensive testing
- ✅ Peer connection management and DNS seed resolution
- ✅ Network service with async peer management
- ✅ Comprehensive test suite for networking components

**Phase 2 Complete**: Blockchain Synchronization

- ✅ Block storage with RocksDB backend
- ✅ Block index implementation with height/hash lookups
- ✅ Headers-first sync support (`getheaders`/`headers` message handling)
- ✅ Block download and storage (`getdata`/`block` message handling)
- ✅ Block chain operations and ancestor lookups
- ✅ Comprehensive blockchain validation and testing

**Phase 3.1 Complete**: Basic Block Validation

- ✅ Proof-of-work verification
- ✅ Block structure and size validation
- ✅ Merkle root validation
- ✅ Difficulty adjustment validation

**Phase 3.2-3.3 Pending**: Transaction Validation & UTXO Management

- ⏳ Transaction input/output validation
- ⏳ Script execution using `bitcoin` crate
- ⏳ Signature verification (ECDSA, Schnorr)
- ⏳ Timelock validation (nLockTime, nSequence)
- ⏳ UTXO set management and tracking

**Phase 4 In Progress**: Mempool & Transaction Relay

- 🔄 Mempool structure implemented
- 🔄 Transaction validation against UTXO set
- ⏳ Transaction relay and propagation (pending)

**Phase 5 Planned**: Advanced Features & Mainnet

- ⏳ BIP-specific consensus rules
- ⏳ SegWit and Taproot validation
- ⏳ Network hardening and DoS protection
- ⏳ Mainnet support
- ⏳ Optional RPC interface

## Project Structure

```
bitcoin-rs/
├── Cargo.toml
├── src/
│   ├── main.rs              # Entry point with network service
│   ├── config.rs            # Network configuration (testnet/mainnet)
│   ├── network/             # P2P networking ✅
│   │   ├── mod.rs           # Module exports
│   │   ├── peer.rs          # Peer connection management
│   │   ├── message.rs       # Bitcoin message serialization
│   │   ├── peer_manager.rs  # Peer pool management
│   │   ├── handshake.rs     # Version handshake protocol
│   │   ├── keepalive.rs     # Ping/pong mechanism
│   │   ├── dns_seeds.rs     # DNS seed resolution
│   │   └── service.rs       # Network service coordinator
│   ├── blockchain/          # Block storage and validation ✅
│   │   ├── mod.rs           # High-level blockchain interface
│   │   ├── block_index.rs   # Block indexing and lookups
│   │   └── validation.rs    # Consensus validation rules
│   ├── mempool/             # Transaction pool 🔄
│   │   ├── mod.rs           # Mempool interface
│   │   └── validation.rs    # Transaction validation
│   ├── consensus/           # Consensus rules ✅
│   │   ├── mod.rs           # Consensus module
│   │   └── params.rs        # Network parameters
│   ├── storage/             # Database layer ✅
│   │   ├── mod.rs           # Storage interface
│   │   └── db.rs            # RocksDB implementation
│   └── rpc/                 # Optional RPC server ⏳
│       └── mod.rs           # RPC interface (planned)
├── tests/                   # Integration tests ✅
│   ├── keepalive_*.rs       # Keepalive mechanism tests
│   ├── network_integration.rs
│   └── version_handshake_integration.rs
└── README.md
```

**Legend**: ✅ Complete | 🔄 In Progress | ⏳ Planned

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

1. **Phase 1**: Foundation & P2P Networking ✅ **COMPLETE**

   - Bitcoin message serialization/deserialization
   - Version handshake and keepalive mechanisms
   - Peer connection management and DNS seed resolution
   - Comprehensive test suite

2. **Phase 2**: Blockchain Synchronization ✅ **COMPLETE**

   - Block storage with RocksDB backend
   - Block indexing and chain operations
   - Headers-first sync support
   - Block download and validation

3. **Phase 3**: Block & Transaction Validation 🔄 **PARTIAL**

   - Phase 3.1: Basic block validation ✅ Complete
   - Phase 3.2: Transaction validation ⏳ Pending
   - Phase 3.3: UTXO set management ⏳ Pending

4. **Phase 4**: Mempool & Transaction Relay 🔄 **IN PROGRESS**

   - Mempool structure implemented
   - Transaction validation against UTXO set
   - Transaction relay and propagation (pending)

5. **Phase 5**: Advanced Features & Mainnet ⏳ **PLANNED**
   - BIP-specific consensus rules
   - SegWit and Taproot validation
   - Network hardening and mainnet support

## Current Capabilities

The Bitcoin Rust node currently supports:

- **Full P2P Networking**: Connect to Bitcoin testnet peers, exchange messages, maintain connections
- **Blockchain Storage**: Store and retrieve blocks using RocksDB with efficient indexing
- **Block Validation**: Basic consensus validation including proof-of-work, merkle trees, and difficulty
- **Transaction Validation**: ⏳ Pending (Phase 3.2)
- **UTXO Management**: ⏳ Pending (Phase 3.3)
- **Chain Operations**: Block height lookups, ancestor queries, and chain statistics

## Testing

The project includes comprehensive testing:

- **Unit Tests**: Individual component testing with mock data
- **Integration Tests**: End-to-end testing of networking and blockchain components
- **Keepalive Tests**: Specialized tests for peer connection management
- **Network Tests**: Version handshake and peer integration testing

Run tests with:

```bash
cargo test
```

See `PLAN.md` for detailed implementation roadmap.
