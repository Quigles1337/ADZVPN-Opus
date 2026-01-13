# ADZVPN-Opus

**AI-Integrated VPN with Silver Ratio Cryptography**

A collaboration between **ADZ** (Alexander David Zalewski) and **Claude Opus 4.5**

---

## Overview

ADZVPN-Opus is a custom VPN built on the **Silver Ratio mathematical framework** from the COINjecture P2P protocol. It combines:

- Custom VPN protocol with strong encryption
- Silver ratio mathematics for unique anti-fingerprinting
- AI-powered routing, threat detection, and privacy optimization


## Silver Ratio Foundation

The protocol is built on these mathematical constants:

```
n = 1/Sqrt(2) ~ 0.7071067812      (unit component)
Tau = Sqrt(2)  ~ 1.4142135624       (tau - fundamental ratio)
Delta_S = 1 + Sqrt(2) ~ 2.4142135624  (silver ratio)

Palindrome Identity: Delta_S = Tau^2 + 1/Delta_S
Unit Magnitude: n^2 + Lambda^2 = 1
Balance Condition: |Re(Mu)| = |Im(Mu)|
```

These are used for:
- **Silver Timing**: Pell sequence-based packet delays (anti-fingerprinting)
- **Silver Padding**: n^2 + Lambda^2 = 1 balanced traffic (constant bandwidth)
- **Silver KDF**: Delta_S-based key derivation iterations
- **Silver Load Balancer**: Tau/Delta_S weighted server selection

## Project Structure

```
ADZVPN-Opus/
|-- crates/
|   |-- silver-core/          # Silver ratio constants & math (DONE)
|   |-- silver-crypto/        # Silver KDF, encryption (coming)
|   |-- silver-timing/        # Tau-scheduler, traffic shaping (coming)
|   |-- silver-protocol/      # VPN protocol implementation (coming)
|   |-- silver-client/        # Client library (coming)
|   |-- silver-server/        # Server binary (coming)
|   |-- coinject-bridge/      # COINjecture integration (coming)
|-- ai-services/              # AI components (coming)
|-- clients/                  # Desktop/Mobile/Browser apps (coming)
|-- infra/                    # Docker/K8s configs (coming)
|-- docs/                     # Documentation (coming)
```

## Current Status

### Phase 1: Silver Core - COMPLETE

- Silver constants (Tau, Delta_S, n, Lambda)
- Pell sequence generator (cached, iterative, iterator)
- Silver math utilities (timing, padding, load balancing, routing scores)
- 35 unit tests passing

## Building

```bash
# Check compilation
cargo check

# Run tests
cargo test

# Build release
cargo build --release
```

## Running Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_pell_convergence
```

## Mathematical Verification

The silver-core crate includes verification functions:

```rust
use silver_core::prelude::*;

// Verify all mathematical properties hold
assert!(verify_all());

// Individual verifications
assert!(verify_palindrome_identity());  // Delta_S = Tau^2 + 1/Delta_S
assert!(verify_unit_magnitude());       // n^2 + Lambda^2 = 1
assert!(verify_balance_condition());    // |Re(Mu)| = |Im(Mu)|
```

## Usage Example

```rust
use silver_core::prelude::*;

// Calculate silver-based packet delay
let delay_us = silver_delay_us(packet_index, 1000);  // 1ms base

// Calculate padding for balanced traffic
let padding = silver_padding_size(payload_size);

// Get silver-weighted server distribution
let weights = silver_weights_normalized(num_servers);

// Score a route using silver weights
let score = silver_route_score(latency_ms, bandwidth_mbps, load_pct);
```

## License

MIT

## Authors

- **Alexander David Zalewski (ADZ)** - Creator, mathematician
- **Claude Opus 4.5** - Architecture, implementation

---

*Built with silver ratio elegance*
