# `diblib` — Technical Architecture & Protocol Specification

> **Purpose of this Document:** This file is the authoritative specification for `diblib`, the schema-agnostic peer-to-peer cryptographic DAG, storage, and Hex-Mesh networking library powering **dibsy** and third-party decentralized applications. Both human contributors and AI coding agents must adhere to the invariants, wire formats, and trait boundaries defined here.

---

## 1. System Overview & Core Invariants

`diblib` is a dual-target Rust P2P engine (`std` native + `wasm32-unknown-unknown`) that provides:
1. **Schema-Agnostic Cryptographic DAG:** Applications define their own payload and graph reference types via the `AppSchema` trait. `diblib` handles deterministic CBOR serialization, `ed25519` signing, subkey delegation, Hybrid Logical Clocks (HLC), and End-to-End Encryption (E2EE).
2. **Header/Body Split for Mutable Lifecycles:** Every record is split into a compact ~180-byte signed `EnvelopeHeader` and a detachable `EnvelopeBody`. This enables cryptographically verified **Edits**, **Tombstones (deletions)**, and **Header-First Sync** without breaking DAG references.
3. **Verified Media & Asset Streaming:** Attached files (images, video, audio, WASM plugins, game builds) are content-addressed and streamed in parallel using `BLAKE3` Bao Merkle trees (`bao-tree`).
4. **Hex-Mesh Small-World Topology:** Peers organize into local 6-node cliques (**Hexagons**, $K_6$) for instant 1-hop local gossip, bridged by Kademlia-style XOR long-range shortcuts and high-availability **Pillar** super-peers for $O(\log N)$ global routing.
5. **Organic "Non-Propagation" Moderation:** Storage engines track a **Vitality Score** per envelope. Unpropagated or actively suppressed envelopes decay below the garbage-collection threshold and have their bodies/blobs automatically evicted.

### Hard Architectural Invariants (Rules for Coding Agents)
* **No Application Leakage:** Never hardcode `dibsy`-specific concepts (such as usernames, posts, likes, or chat channels) inside `diblib`. All domain logic belongs in the consumer crate implementing `AppSchema`.
* **Deterministic CBOR Only:** Signatures and `EnvelopeId` hashes are computed over deterministic `minicbor` bytes. Never re-serialize a received header to verify its signature; always hash the exact canonical bytes or enforce strict deterministic field ordering (`#[n(0)]`, `#[n(1)]`, ...).
* **Strict WASM Compatibility:** `diblib-wire` must remain `#![no_std]` (with `alloc`). `diblib-store`, `diblib-net`, and `diblib-sdk` must compile cleanly on both `x86_64`/`aarch64` native targets and `wasm32-unknown-unknown` without relying on `std::time::Instant`, `std::fs`, or OS threads on WASM.
* **Zero JSON on the Wire or IPC:** All network packets, disk records, and Tauri/Worker IPC boundaries exchange raw `minicbor` bytes (`Uint8Array` / `&[u8]`).

---

## 2. Cargo Workspace Architecture

```text
diblib/
├── Cargo.toml                 # Workspace root (Edition 2024, MSRV 1.85+)
├── SPEC.md                    # This specification
└── crates/
    ├── diblib-wire/           # [no_std + alloc] Envelopes, Crypto, HLC, E2EE, Traits
    ├── diblib-store/          # [std + wasm32] StorageBackend, Redb, IndexedDB/OPFS, IBLT, GC
    ├── diblib-net/            # [std + wasm32] libp2p HexMeshBehaviour, /diblib/* protocols
    └── diblib-sdk/            # [std + wasm32] High-level DibNode<S: AppSchema> API
```

### Root `Cargo.toml` Dependencies

```toml
[workspace]
resolver = "3"
members = [
    "crates/diblib-wire",
    "crates/diblib-store",
    "crates/diblib-net",
    "crates/diblib-sdk",
]

[workspace.package]
edition = "2024"
rust-version = "1.85"
license = "MIT OR Apache-2.0"

[workspace.dependencies]
minicbor = { version = "2.3.0", default-features = false, features = ["alloc", "derive"] }
ed25519-dalek = { version = "3.0.0", default-features = false, features = ["alloc", "rand_core", "zeroize"] }
x25519-dalek = { version = "3.0.0", default-features = false, features = ["zeroize", "getrandom", "static_secrets"] }
chacha20poly1305 = { version = "0.10", default-features = false, features = ["alloc", "getrandom"] }
blake3 = { version = "1.8.7", default-features = false }
bao-tree = { version = "0.16", default-features = false, features = ["tokio_fsm"] }
thiserror = { version = "2.0", default-features = false }
```

---

## 3. Crate 1: `diblib-wire` (Cryptographic Primitives & Envelopes)

### 3.1 The `AppSchema` Trait

Any application built on `diblib` implements `AppSchema`:

```rust
use minicbor::{Decode, Encode};

pub trait AppSchema: Send + Sync + Sized + 'static {
    /// Domain payload stored in EnvelopeBody (e.g., Post, Profile, DibsClaim, ChatMsg)
    type Payload: for<'a> Encode<()> + for<'a> Decode<'a, ()> + Clone + Send + Sync;

    /// Directed graph edge type stored in EnvelopeHeader (e.g., Reply, Like, Follow)
    type RefKind: for<'a> Encode<()> + for<'a> Decode<'a, ()> + Copy + Eq + Ord + Send + Sync;

    /// Ephemeral datagram payload sent over `/diblib/fast/1.0.0` (e.g., VoiceFrame, GameTick)
    type FastPacket: for<'a> Encode<()> + for<'a> Decode<'a, ()> + Clone + Send + Sync;
}
```

### 3.2 Identity & Multi-Device Subkey Delegation

Users hold a root `ed25519` keypair (`MasterPubKey = [u8; 32]`). To avoid copying master private keys across browsers, laptops, and phones, the root key signs a `DeviceCertificate` delegating authority to a device-specific `ed25519` keypair (`DevicePubKey = [u8; 32]`) and an `x25519` encryption public key (`DeviceDhPubKey = [u8; 32]`).

```rust
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct DeviceCertificate {
    #[n(0)] pub master_pubkey: [u8; 32],
    #[n(1)] pub device_sign_pubkey: [u8; 32],
    #[n(2)] pub device_dh_pubkey: [u8; 32],
    #[n(3)] pub issued_at_hlc: u64,
    #[n(4)] pub expires_at_hlc: u64,
    #[n(5)] pub capabilities: u32,        // Bitflags (e.g., CAN_PUBLISH, CAN_DM, CAN_TOMBSTONE)
    #[n(6)] pub master_signature: [u8; 64], // Signed over minicbor(fields 0..=5)
}
```

### 3.3 Hybrid Logical Clock (`HlcTimestamp`)

Packed into a single `u64`:
* **Upper 48 bits:** Physical Unix epoch time in milliseconds.
* **Lower 16 bits:** Logical monotonic counter for causal ordering within the same millisecond.
* **Drift Rule:** Reject incoming envelopes whose physical timestamp is more than **300,000 ms (5 minutes)** ahead of local wall-clock time.

### 3.4 Envelope Header, Body & Lifecycle Operations

```rust
pub type EnvelopeId = [u8; 32]; // BLAKE3 hash of canonical minicbor(EnvelopeHeader)
pub type BaoRoot = [u8; 32];    // BLAKE3 Bao Merkle root hash

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub enum LifecycleOp {
    /// Standard creation of a new DAG node
    #[n(0)] Publish,

    /// Replaces the body/blobs of `target_id` while preserving its incoming graph edges.
    /// VALIDATION: `header.author_pubkey` MUST equal `target.header.author_pubkey`.
    #[n(1)] Edit {
        #[n(0)] target_id: EnvelopeId,
    },

    /// Purges the body/blobs of `target_id` across honest nodes and Archive Pillars.
    /// VALIDATION: `header.author_pubkey` MUST equal `target.header.author_pubkey`.
    #[n(2)] Tombstone {
        #[n(0)] target_id: EnvelopeId,
    },

    /// Soft non-propagation / moderation signal emitted by any peer.
    /// Reduces `target_id`'s Vitality Score in receiving peers' storage engines.
    #[n(3)] Suppress {
        #[n(0)] target_id: EnvelopeId,
        #[n(1)] reason_code: u16,
    },
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TypedRef<R> {
    #[n(0)] pub kind: R,
    #[n(1)] pub target_id: EnvelopeId,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct BlobDescriptor {
    #[n(0)] pub bao_root: BaoRoot,
    #[n(1)] pub size_bytes: u64,
    #[n(2)] pub mime_hint: u16,
    #[n(3)] pub is_encrypted: bool,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeHeader<R> {
    #[n(0)] pub version: u8,                           // Protocol version = 1
    #[n(1)] pub author_pubkey: [u8; 32],               // Root MasterPubKey
    #[n(2)] pub device_cert: Option<DeviceCertificate>,// Present if signed by delegated subkey
    #[n(3)] pub hlc_timestamp: u64,
    #[n(4)] pub topic_tag: [u8; 32],                   // Swarm/Hexagon routing affinity hash
    #[n(5)] pub op: LifecycleOp,
    #[n(6)] pub refs: Vec<TypedRef<R>>,
    #[n(7)] pub blobs: Vec<BlobDescriptor>,
    #[n(8)] pub body_hash: [u8; 32],                   // blake3(minicbor(EnvelopeBody)), or [0; 32] if empty
}

#[derive(Encode, Decode, Clone, Debug)]
pub struct Envelope<S: AppSchema> {
    #[n(0)] pub id: EnvelopeId,
    #[n(1)] pub signature: [u8; 64],                   // Ed25519 signature over `id`
    #[n(2)] pub header: EnvelopeHeader<S::RefKind>,
    #[n(3)] pub body: Option<EnvelopeBody<S::Payload>>,
}
```

### 3.5 End-to-End Encryption (`EnvelopeBody`)

```rust
#[derive(Encode, Decode, Clone, Debug)]
pub enum EnvelopeBody<P> {
    /// Public cleartext payload
    #[n(0)] Cleartext(#[n(0)] P),

    /// 1-to-1 E2EE: X25519 Ephemeral ECDH -> HKDF-BLAKE3 -> ChaCha20-Poly1305
    #[n(1)] DirectEncrypted {
        #[n(0)] recipient_dh_pubkey: [u8; 32],
        #[n(1)] ephemeral_dh_pubkey: [u8; 32],
        #[n(2)] nonce: [u8; 12],
        #[n(3)] ciphertext: Vec<u8>, // Decrypts to minicbor(P)
    },

    /// Multi-recipient E2EE (Friends-Only Feeds, Private Channels/Guilds)
    /// Encrypted with a shared 32-byte symmetric EpochKey rotated on member removal
    #[n(2)] GroupEncrypted {
        #[n(0)] group_id: [u8; 32],
        #[n(1)] key_epoch: u32,
        #[n(2)] nonce: [u8; 12],
        #[n(3)] ciphertext: Vec<u8>, // Decrypts to minicbor(P)
    },
}
```

#### Cryptographic Construction for `DirectEncrypted`:
1. Generate a single-use `x25519_dalek::EphemeralSecret` and corresponding `ephemeral_dh_pubkey`.
2. Compute `shared_secret = ephemeral_secret.diffie_hellman(&recipient_dh_pubkey)`.
3. Derive a 32-byte key via `blake3::derive_key("diblib-direct-e2ee-v1", shared_secret.as_bytes())`.
4. Encrypt the deterministic `minicbor` bytes of `P` using `ChaCha20Poly1305` with a random 96-bit `nonce` and `header.author_pubkey` as Associated Data (AAD).

#### Private Blobs:
When a blob belongs to a `DirectEncrypted` or `GroupEncrypted` envelope:
1. Encrypt the raw file first with a random 32-byte `blob_key` and 12-byte `blob_nonce` using `ChaCha20Poly1305` (or streaming `XChaCha20Poly1305` in 64 KiB segments).
2. Compute the `bao_root` over the **ciphertext** and set `BlobDescriptor.is_encrypted = true`.
3. Place `(bao_root, blob_key, blob_nonce)` inside the encrypted payload `P`. Archive Pillars can validate and serve the `bao-tree` slices without ever seeing the plaintext media.

---

## 4. Crate 2: `diblib-store` (Storage, Compaction & Set Reconciliation)

### 4.1 The `StorageBackend` Trait

Because browser IndexedDB/OPFS operations are asynchronous, `StorageBackend` uses native Rust 2024 `async fn` in traits (with `Send` bounds gated via a `MaybeSend` marker trait for `wasm32` compatibility):

```rust
pub trait StorageBackend<S: AppSchema>: Sized {
    async fn put_envelope(&self, env: &Envelope<S>) -> Result<PutOutcome, StoreError>;
    async fn get_header(&self, id: &EnvelopeId) -> Result<Option<EnvelopeHeader<S::RefKind>>, StoreError>;
    async fn get_envelope(&self, id: &EnvelopeId) -> Result<Option<Envelope<S>>, StoreError>;
    async fn get_latest_edit(&self, original_id: &EnvelopeId) -> Result<Option<Envelope<S>>, StoreError>;
    async fn query_by_ref(&self, kind: S::RefKind, target: &EnvelopeId) -> Result<Vec<EnvelopeId>, StoreError>;
    async fn query_by_topic(&self, topic: &[u8; 32], since_hlc: u64, limit: usize) -> Result<Vec<EnvelopeId>, StoreError>;

    // Bao Blob Storage (64 KiB chunk group granularity)
    async fn put_bao_slice(&self, root: &BaoRoot, slice_bytes: &[u8]) -> Result<(), StoreError>;
    async fn get_bao_slice(&self, root: &BaoRoot, offset: u64, len: u64) -> Result<Option<Vec<u8>>, StoreError>;

    // Vitality & Compaction
    async fn record_propagation(&self, id: &EnvelopeId, peer_trust: f32) -> Result<(), StoreError>;
    async fn run_vitality_gc(&self, now_ms: u64, threshold: f32) -> Result<GcStats, StoreError>;
}
```

### 4.2 Concrete Storage Implementations
1. **Native (`RedbStore`):**
   * Uses `redb` tables: `headers` (`EnvelopeId -> bytes`), `bodies` (`EnvelopeId -> bytes`), `edges` (`(TargetId, RefKind, Hlc) -> EnvelopeId`), `edits` (`OriginalId -> LatestEditId`), `tombstones` (`TargetId -> TombstoneEnvelopeId`), and `vitality` (`EnvelopeId -> VitalityRecord`).
   * Stores `bao-tree` outboard files and raw data blobs in `<data_dir>/blobs/<first_2_hex>/<bao_root>.blob`.
2. **Browser WASM (`WebStore`):**
   * Stores headers, bodies, and index tables inside **IndexedDB**.
   * Stores large media blobs inside **OPFS (Origin Private File System)** via synchronous `FileSystemSyncAccessHandle` inside the dedicated Web/SharedWorker.

### 4.3 Lifecycle Compaction Rules (`Edit` & `Tombstone`)
* **On receiving `LifecycleOp::Tombstone { target_id }`:**
  1. Verify the signature and verify that `tombstone.header.author_pubkey == target.header.author_pubkey`.
  2. Immediately delete `target_id` (and any prior `Edit`s of `target_id`) from the `bodies` table and delete its unreferenced `blobs` from disk/OPFS.
  3. Retain `target_id`'s 180-byte `EnvelopeHeader` and the `Tombstone` header so future sync attempts recognize the deletion and refuse to re-ingest the deleted body.
* **On receiving `LifecycleOp::Edit { target_id }`:**
  1. Verify the signature and author match.
  2. If `edit.header.hlc_timestamp` is newer than the current latest edit for `target_id`, update the `edits` pointer table and purge the superseded body bytes.

### 4.4 Vitality Score & Non-Propagation Garbage Collection

Every stored body/blob (except items authored by or explicitly pinned by the local user) has a dynamic Vitality Score:

$$\text{Vitality}(p) = \frac{\sum_{i \in \text{Seeders}(p)} w_i}{\left(\frac{\text{now} - t_p}{\tau} + 1\right)^\gamma + \sum_{j \in \text{Suppressors}(p)} w_j}$$

Where:
* $w_i, w_j \in [0.1, 1.0]$ are local social-trust weights (1.0 for directly followed peers, 0.25 for 2-hop peers, 0.1 for unknown peers).
* $\tau = 86,400,000\text{ ms}$ (1 day scale factor) and $\gamma = 1.5$ (time decay exponent).
* When `run_vitality_gc` executes and $\text{Vitality}(p) < \text{threshold}$, `diblib-store` purges the `EnvelopeBody` and associated media `blobs`, converting the record into a header-only stub.

---

## 5. Crate 3: `diblib-net` (Hex-Mesh Topology & Wire Protocols)

`diblib-net` wraps `rust-libp2p` using a custom `NetworkBehaviour` named `HexMeshBehaviour`. We do **not** use `libp2p-gossipsub`.

### 5.1 Transport Stack
* **Native (`std`):** QUIC (`libp2p-quic`), WebRTC (`libp2p-webrtc`), WebTransport, plus Noise encryption and Yamux stream multiplexing.
* **Browser (`wasm32`):** Browser WebRTC (`libp2p-webrtc-websys`) for direct browser-to-browser data channels, and WebTransport (`libp2p-webtransport-websys`) for connecting to Pillars.

### 5.2 The Hex-Mesh Topology State Machine

Each peer has a `PeerId` mapped into a 256-bit keyspace via `blake3(peer_pubkey)` and maintains a target of **8 to 9 active connections**:

| Slot Group | Target Connections | Selection & Replacement Rule |
| :--- | :--- | :--- |
| **Intra-Hexagon Clique ($K_6$)** | **5 peers** | Peers sharing the same active `topic_tag` (or social graph overlap) form a fully connected 6-node hexagon. Every member exchanges their 5-peer roster via `/diblib/hex/1.0.0` so missing triangle edges are dialed immediately. |
| **Inter-Hexagon XOR Bridges** | **2–3 peers** | Selected from Kademlia-style XOR distance buckets ($d(\text{self}, \text{peer}) \approx 2^{256 - k}$) to guarantee $O(\log N)$ global small-world diameter and resist Eclipse attacks. |
| **Pillar Anchors** | **1–2 Pillars** | Persistent links to at least one **Compass Pillar** (signaling/NAT relay) and one **Archive/Registry Pillar** discovered via `ServiceManifest`. |

### 5.3 Wire Protocols (`minicbor` Framed Streams)

All stream messages are prefixed with an unsigned `leb128` byte-length header (max frame size: 256 KiB) followed by deterministic `minicbor` bytes.

#### 1. `/diblib/hex/1.0.0` — Hexagon Formation & Pillar Discovery
```rust
#[derive(Encode, Decode, Clone, Debug)]
pub enum HexControlMsg {
    /// Announces current intra-hexagon members and active topic affinity
    #[n(0)] CliqueRoster {
        #[n(0)] hexagon_id: [u8; 16],
        #[n(1)] topic_tag: [u8; 32],
        #[n(2)] members: Vec<PeerDescriptor>, // Max 6 members
    },
    /// Queries or returns peers at specific XOR distance buckets + known Pillars
    #[n(1)] FindXorPeers {
        #[n(0)] target_key: [u8; 32],
        #[n(1)] capability_filter: Option<String>,
    },
    #[n(2)] XorPeersResponse {
        #[n(0)] peers: Vec<PeerDescriptor>,
        #[n(1)] pillars: Vec<ServiceManifest>,
    },
}
```

#### 2. `/diblib/gossip/1.0.0` — Header-First Push / Pull Gossip
1. **Push Header:** When a peer publishes or decides to propagate an envelope, it sends `GossipMsg::AnnounceHeader(EnvelopeHeader, id, signature)` to its 5 intra-hex peers and 2–3 XOR bridges.
2. **Filter Check:** The receiving peer verifies the `ed25519` signature, checks if `id` already exists in `StorageBackend`, and checks if `id` is Tombstoned or locally Suppressed.
3. **Pull Body:** If the header is new and wanted, the receiver replies with `GossipMsg::FetchBody(id)` and receives `GossipMsg::BodyPayload(EnvelopeBody)`.

#### 3. `/diblib/sync/1.0.0` — Single-Round-Trip IBLT Set Reconciliation
When a node wakes up from offline sleep or joins a new Hexagon:
1. Initiator sends `SyncRequest { topic_tag, hlc_range: (start, end), iblt_sketch: Vec<u8> }` (a 2 KiB Invertible Bloom Lookup Table encoding the XOR sum of known `EnvelopeId`s in that window).
2. Responder subtracts its own local IBLT sketch from the initiator's sketch and peels the difference set:
   * Immediately pushes headers the initiator is missing.
   * Requests `EnvelopeId`s that the initiator has which the responder is missing.

#### 4. `/diblib/bao/1.0.0` — Verified Parallel Media Streaming
```rust
#[derive(Encode, Decode, Clone, Debug)]
pub struct BaoSliceRequest {
    #[n(0)] pub bao_root: BaoRoot,
    #[n(1)] pub start_chunk: u32, // 1 chunk = 1024 bytes; 1 chunk group = 64 KiB
    #[n(2)] pub chunk_count: u32,
}
```
The responder streams back a self-verifying `bao_tree` slice containing the internal Merkle parent hashes and raw chunk bytes. The requester verifies the slice against `bao_root` in memory before writing to disk/OPFS; if verification fails, the peer is immediately disconnected and banned.

#### 5. `/diblib/fast/1.0.0` — The Ephemeral Fast Lane
* Uses unreliable WebRTC `RTCDataChannel` (`ordered: false, maxRetransmits: 0`) on browser/WebRTC links and QUIC `datagram` frames on native links.
* Transports `FastEnvelope<S::FastPacket>` (signed or session-MAC authenticated with a 32-bit sequence number) for live voice/video SFU packets, typing indicators, and authoritative multiplayer Game Pillar state ticks without touching `StorageBackend`.

### 5.4 Extensible Pillar `ServiceManifest`

Any Pillar (built-in or third-party) advertises its capabilities using a signed `ServiceManifest`:

```rust
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct ServiceManifest {
    #[n(0)] pub pillar_pubkey: [u8; 32],
    #[n(1)] pub multiaddrs: Vec<String>,
    /// Reverse-DNS capability strings, e.g.:
    /// - "org.dibsy.compass.v1"  (WebRTC Signaling, Bootstrap, NAT Relay)
    /// - "org.dibsy.archive.v1"  (DAG & Bao Blob Pinning, Store-and-Forward Inbox)
    /// - "org.dibsy.registry.v1" (PoW Username Dibs Quorum Log)
    /// - "org.dibsy.index.v1"    (Full-Text Search & Feed Candidate Pools)
    /// - "org.dibsy.oracle.v1"   (Opt-in Open-Weight AI Inference RPC)
    /// - "org.dibsy.stage.v1"    (WebRTC Voice/Video SFU)
    /// - Custom third-party strings (e.g., "net.mygame.matchmaker.v1")
    #[n(2)] pub capabilities: Vec<String>,
    #[n(3)] pub max_storage_bytes: u64,
    #[n(4)] pub timestamp_hlc: u64,
    #[n(5)] pub signature: [u8; 64],
}
```

---

## 6. Crate 4: `diblib-sdk` (Public Consumer API)

`diblib-sdk` exposes a unified, runtime-agnostic handle (`DibNode<S: AppSchema>`) used identically by the native Tauri v2 backend, the Browser SharedWorker, and the `dibsy-pillar` server binary:

```rust
pub struct DibNode<S: AppSchema> { /* internal command channel + shared store */ }

impl<S: AppSchema> DibNode<S> {
    pub fn builder() -> DibNodeBuilder<S>;

    /// Publishes a new cleartext, direct-encrypted, or group-encrypted envelope
    pub fn publish(&self) -> PublishBuilder<'_, S>;

    /// Broadcasts an Edit or Tombstone for an existing envelope authored by this user
    pub async fn edit(&self, target_id: EnvelopeId, new_payload: S::Payload) -> Result<EnvelopeId, DibError>;
    pub async fn tombstone(&self, target_id: EnvelopeId) -> Result<EnvelopeId, DibError>;

    /// Emits a non-propagation suppression signal and purges local body/blobs
    pub async fn suppress(&self, target_id: EnvelopeId, reason_code: u16) -> Result<(), DibError>;

    /// Chunks, hashes (and optionally encrypts) a media blob into local Bao storage
    pub async fn store_blob(&self, data: &[u8], mime_hint: u16, encrypt: bool) -> Result<BlobDescriptor, DibError>;

    /// Streams verified bytes of a remote or local Bao blob
    pub async fn read_blob_range(&self, root: BaoRoot, offset: u64, len: u64) -> Result<Vec<u8>, DibError>;

    /// Sends an ephemeral zero-storage packet over the `/diblib/fast/1.0.0` lane
    pub async fn send_fast(&self, target_peer: [u8; 32], packet: S::FastPacket) -> Result<(), DibError>;

    /// Subscribes to incoming verified envelopes, fast packets, and topology events
    pub fn subscribe_events(&self) -> Receiver<DibEvent<S>>;
}
```

---

## 7. Implementation Checklist for Coding Agents

Execute these milestones sequentially. Every step must pass `cargo test --workspace` and `cargo check --target wasm32-unknown-unknown` before advancing.

- [ ] **Milestone 1 (`diblib-wire`):**
  - [ ] Implement `HlcTimestamp` generator with monotonic counter and 5-minute drift guard.
  - [ ] Implement `AppSchema`, `EnvelopeHeader`, `EnvelopeBody`, `LifecycleOp`, and deterministic `minicbor` serialization helpers.
  - [ ] Implement `MasterIdentity` and `DeviceCertificate` generation, signing, and verification with `ed25519-dalek`.
  - [ ] Implement `DirectEncrypted` (`x25519-dalek` + `blake3::derive_key` + `chacha20poly1305`) and `GroupEncrypted` helpers with unit test round-trips.
- [ ] **Milestone 2 (`diblib-store`):**
  - [ ] Define `StorageBackend<S>` and implement `InMemoryStore` (for fast deterministic multi-node simulation tests) and `RedbStore` (for native/Pillar persistence).
  - [ ] Implement `bao-tree` 64 KiB chunk group slicing, outboard storage, and partial slice verification.
  - [ ] Implement `LifecycleOp::Edit` and `LifecycleOp::Tombstone` compaction logic and verify that deleted bodies cannot be re-inserted by stale peers.
  - [ ] Implement the Vitality Score calculator, `Suppress` weight decay, and IBLT 2 KiB sketch encoder/decoder.
- [ ] **Milestone 3 (`diblib-net`):**
  - [ ] Implement the `minicbor` length-prefixed codec and `/diblib/gossip/1.0.0` + `/diblib/sync/1.0.0` + `/diblib/bao/1.0.0` handlers inside `HexMeshBehaviour`.
  - [ ] Implement `/diblib/hex/1.0.0` $K_6$ clique slot negotiation and XOR bucket routing table maintenance.
  - [ ] Implement `/diblib/fast/1.0.0` unreliable datagram routing.
- [ ] **Milestone 4 (`diblib-sdk` & Browser WASM Store):**
  - [ ] Implement `WebStore` (IndexedDB + OPFS) for `wasm32-unknown-unknown`.
  - [ ] Expose `DibNode<S>` builder and write a 20-node local Hex-Mesh integration test verifying 1-hop intra-hex gossip, multi-hop XOR routing, media streaming, and Tombstone propagation.