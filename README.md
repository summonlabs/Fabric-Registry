# Fabric Registry

Fabric Registry is the canonical identity and registration runtime of the
Distributed Fabric Infrastructure ("Fabric OS") stack. It answers one question:

> What fabric infrastructure entities exist under this authority domain, what are
> their canonical identities and current generations, who is authorized to
> register or mutate those identities, what evidence supports each registration,
> and when must a registration be rejected, retired, superseded, fenced, or
> revalidated?

It is a vendor-neutral C++20 library with a small set of executables. It has no
third-party dependencies.

Version 1.0.0. Persisted state format version 1. Wire protocol version 1.

---

## 1. Systems boundary

Fabric Registry establishes **what something is** and **whether that identity
record is current and authoritative**.

### It owns

* Canonical, strongly typed identity for fabric infrastructure entities.
* The lifecycle of an identity record: current, superseded, retired, tombstoned.
* Registration authority: which publisher, under which process incarnation and
  which coordinator epoch, may create or mutate a record.
* Evidence provenance and the freshness rules that decide whether a record may
  still be treated as current.
* Reconciliation: deciding whether an observation refers to an existing entity,
  is a conflict, or is something new.
* Versioned, integrity-checked durable state and conservative recovery.

### It explicitly does not own

| Adjacent runtime | What it owns, and this repository does not |
| --- | --- |
| Fabric Topology | The dynamic graph connecting registered entities |
| Link State Fabric | Live link up/down/degraded state, loss, latency, congestion |
| Port Fabric | Operational and configuration semantics beyond port identity |
| Fabric Capability Registry | What a device *can* do |
| Failure Domain Registry | Failure containment domains |
| Fabric Epoch | Fabric-wide time and epoch authority for the data plane |
| Path Authority | Which paths are permitted |
| Route Fabric | Route computation and programming |

Fabric Registry records a link's canonical identity and the endpoint claims that
define it. It never records whether that link is up. A device being discovered
never makes its registration authoritative, and a recovered record never proves
that the physical device is present.

---

## 2. Why canonical identity needs generations and authority

Identity is not discovery, presence, reachability, health, capability, topology
or authority. Every one of those is a different question, and collapsing them
produces the classic fabric bugs:

* a stale registration replay overwriting a newer generation;
* an alias quietly creating a second physical identity;
* two incompatible devices collapsing into one because they share a name;
* a replacement device inheriting the authority of the port name it took over;
* a restarted process reclaiming live authority it no longer has;
* a registry restart resurrecting process authority that died with its process.

Fabric Registry separates five things that are usually conflated:

1. **Canonical identity** - a class-qualified 128-bit identifier that never
   changes for a given entity.
2. **Generation** - every committed change to a record advances its record
   generation; every acceptance of evidence advances its evidence generation.
   Two counters, because renewing evidence is not an identity change and an
   identity change is not evidence renewal.
3. **Provenance** - where a claim came from, preserved verbatim and never
   upgraded.
4. **Authority** - the publisher, its process incarnation, and the coordinator
   epoch that together entitle a mutation.
5. **Lifecycle** - the state machine that decides what a record means right now.

---

## 3. Architecture

| Header | Contents |
| --- | --- |
| `ids.hpp` | Typed opaque identifiers, monotonic counters, digest domains, CanonicalId, DeviceId, VendorId, ProductId, SerialIdentity |
| `entity_class.hpp` | The entity class taxonomy and its classification predicates |
| `limits.hpp` | RegistryLimits, FrameLimits and the compiled-in hard ceilings |
| `identity.hpp` | Identity facts and canonicalisation, aliases and namespaces, provenance, match classes |
| `errors.hpp` | OutcomeCode, Outcome, deterministic explanation steps |
| `entity.hpp` | Lifecycle, EntityRecord, EvidenceState, LineageEntry, IdempotencyEntry |
| `authority.hpp` | AuthorityClaim, PublisherRecord, publisher state and fencing |
| `registry.hpp` | The Registry API: mutations, queries, snapshots, persistence, diagnostics |
| `snapshot.hpp` | Immutable read snapshots |
| `persistence.hpp` | The versioned on-disk format and its transactional writer |
| `digest.hpp` | SHA-256 and the domain-separated canonical hasher |
| `codec.hpp` | Bounds-checked binary readers and writers |
| `record_codec.hpp` | The single canonical binary encoding of a record |
| `serialization.hpp` | Deterministic text and JSON rendering |
| `frame.hpp` | The wire protocol: framing and every message codec |
| `transport.hpp` | Framed TCP transport with a bounded shutdown path |
| `coordinator.hpp` | The coordinator process |
| `publisher.hpp` | The publisher (worker) client |
| `discovery.hpp` | Platform discovery adapters |
| `fabric_registry.hpp` | Umbrella header |

Source layout: `src/` (library), `tools/` (three executables), `examples/`
(six programs), `tests/` (the proof suite), `benchmarks/` (measured
workloads).

---

## 4. Entity classes

`EntityClass` enumerates what may be registered:

fabric, site, sub-fabric, control-domain, switch, router, nic, smartnic, dpu,
host, port, link, endpoint, control-participant, vendor-device.

`Host` exists to anchor network identities that need a device parent; it is not
a general compute inventory. `VendorDevice` exists for implementation-defined
classes whose identity genuinely needs a registry record. Ports and endpoints
must name the device that owns them, because a port without its parent has no
anchorable identity. A record carries identity and administrative placement only
- never utilization, queue depth, error counters, route state, packet loss,
congestion, health scores or link state.

---

## 5. Identity model

### 5.1 Typed identifiers

Every identity domain has its own C++ type. `FabricId`, `SwitchId`,
`PortId`, `PublisherId`, `WorkerBootId` and the rest are distinct types
with no implicit conversion. `CanonicalId` is the class-qualified
registry-wide identity, rendered as `class:32-lowercase-hex`.
`CanonicalId::of<SwitchId>(id)` and `CanonicalId::as<PortId>()` are the only
conversions, and they are class-checked: `as` returns nullopt for a class
mismatch. The all-zero value is the null id and is rejected wherever a real
identity is required.

Counters (`CoordinatorEpoch`, `RecordGeneration`, `EvidenceGeneration`,
`RegistryGeneration`, `SnapshotSequence`) are 64-bit, monotonic, and
increment through a checked `next()` that returns nullopt at the end of the
space instead of wrapping.

### 5.2 Facts

A record is built from **facts**: `(kind, scope, value)` triples,
canonicalised by `canonicalize_fact`. There are 24 fact kinds.
Canonicalisation is total: for every input there is exactly one of "this is the
canonical form" or "this input is invalid, and here is the specific reason".

| Kind | Canonical form | Strength |
| --- | --- | --- |
| serial-number | trimmed, case preserved, **scope required** | strong |
| device-uuid, switch-guid, port-guid, fabric-guid | `8-4-4-4-12` lowercase | strong |
| chassis-id | trimmed, case preserved | strong |
| pci-address | `dddd:bb:dd.f` lowercase | strong |
| permanent-mac | 12 lowercase hex, **locally administered rejected** | strong |
| device-instance-id | lowercase, scope required | strong |
| slot-id, board-id | trimmed | moderate |
| mac-address | 12 lowercase hex, local bit allowed | moderate |
| inventory-asset-id, cloud-resource-id, port-hardware-name | trimmed | moderate |
| vendor-id, product-id, subsystem-id | `0xhhhh` lowercase, zero rejected | weak |
| device-model, firmware-family, host-name, friendly-name, operator-label, rack-slot-label | trimmed (host-name lowercased) | weak |

A serial number is only unique inside the namespace that issued it, so the scope
is part of the value and part of every index key built from it. A locally
administered MAC is never a permanent identity. Strength is not confidence: a
weak fact can corroborate a match but can never establish one.

### 5.3 Canonical identity derivation

When a request does not name an explicit identifier, the registry derives one:

    CanonicalId = first 16 bytes of SHA-256(
        "fabric-registry/identity-fingerprint/1",
        entity class, derivation namespace,
        sorted strong facts, each length-prefixed)

The administrative namespace is inside the hashed material, so two namespaces
never collide. Derivation requires at least one **strong** fact: identity must
rest on something. The result is deterministic across processes and machines.

The registry is collision-aware: if a derived identifier already exists with a
different fingerprint, the request is refused as a duplicate identity rather
than silently merging or silently duplicating.

### 5.4 Aliases

An alias is a `(namespace, scope, value)` key. There are 13 namespaces, each
with a documented uniqueness scope:

| Namespace | Scope | Unique |
| --- | --- | --- |
| host-name, switch-host-name | fabric | yes |
| vendor-guid, mac-address, cloud-resource-id, external-cmdb-id, dns-name, serial-number | global | yes |
| inventory-asset-id, rack-slot-label, device-instance-id | site | yes |
| port-name | parent device | yes |
| operator-label | - | **no (informational)** |

Only namespaces with a proven uniqueness promise take part in lookup. An
informational alias is stored on the record, is never indexed, and
`lookup_by_alias` refuses it rather than guessing. The canonical text form is
`namespace:scope=value`; the value is everything after the first `=`, so
values may contain `=` and `:`.

An alias bound to a retired or tombstoned record stays reserved. Releasing it is
an explicit `detach_alias` on that record, which is refused for tombstoned and
rejected records. A tombstoned identity's aliases are permanently reserved -
that is what tombstone means.

### 5.5 Provenance

Every material claim preserves: the observation source (operator declaration,
local host enumeration, device agent, controller push, imported inventory,
external CMDB, synthetic fixture, peer registry), the validity class (REAL,
SYNTHETIC, UNSUPPORTED), the mechanism and the source identity. Discovery
sources are never flattened into a single "observed" state. Provenance is
recorded once and never upgraded: a record registered from synthetic input stays
marked synthetic forever. `ProvenanceClass::Unsupported` cannot back a
registered record, and `ProvenanceClass::Unknown` is not evidence.

---

## 6. Reconciliation

`reconcile_observation` decides what an observation means without changing
anything. Registration applies the same decision.

Decisions, in the order the registry evaluates them:

| Match class | Meaning |
| --- | --- |
| exact-canonical | The derived or explicit canonical identity exists and nothing contradicts it. |
| stable-hardware | Strong facts matched exactly with no contradicting fact; the two strong fact sets are subsets of one another. |
| proven-alias | A unique alias resolved to exactly one record and strong facts corroborate it. |
| probable-insufficient | A unique alias or weak facts point at one record, but nothing strong proves it. |
| conflicting | A fact of the same (kind, scope) disagrees with an existing record, or a unique alias points elsewhere. |
| ambiguous | More than one record matched at equal strength. |
| no-match | Nothing in the registry refers to this observation. |

Automatic merging happens only for the first three. A probable match commits
nothing and returns `OutcomeCode::ProbableMatch`; the caller must supply
stronger evidence or resolve explicitly with `ForceNew` or `ForceExisting`.
The reconciliation detail names the candidate records, the conflicting facts,
the conflicting aliases and the observation fingerprint, so two runs can be
compared byte for byte.

Deterministic conflict handling covers same serial with a different
vendor/product scope, the same friendly name with a different stable hardware
identity, an alias colliding across records, contradictory publisher claims,
incomplete hardware identity, and reused operator-visible locations. A
replacement device at the same operator-visible location does **not** inherit
the old record: the old record keeps its identity, and the replacement either
conflicts or becomes a new record.

---

## 7. Lifecycle

    Discovered --> Candidate --> Current
         |             |           |
         |             |           +--> RevalidationRequired --+
         |             |           |            |              |
         |             |           +--> Superseded --> Retired -+
         |             |           |                   |        |
         |             |           +--> Retired -------+------> Tombstoned
         |             |                    ^
         +--> Rejected +--> Conflicted -----+
                            (also --> Current, --> Rejected)

The exact legal transition table, which the test suite asserts for all 81 pairs:

| From | To |
| --- | --- |
| Discovered | Candidate, Current, Conflicted, Rejected |
| Candidate | Current, Conflicted, Rejected |
| Current | RevalidationRequired, Superseded, Retired, Conflicted |
| RevalidationRequired | Current, Superseded, Retired, Conflicted |
| Conflicted | Current, Retired, Rejected |
| Superseded | Retired, Tombstoned |
| Retired | Tombstoned |
| Tombstoned | *(none)* |
| Rejected | *(none)* |

Every illegal transition fails with `OutcomeCode::IllegalTransition`.
Superseded, retired, tombstoned and rejected identities can never regain
current authority: a stale replay aimed at them is rejected before any state is
read for mutation. Identity continuation, replacement generation and a new
identity occupying the same location are three different things and are
represented as three different outcomes.

---

## 8. Authority, incarnation and fencing

A mutation is bound to:

    AuthorityClaim { PublisherId, WorkerBootId, CoordinatorEpoch }

All three are required. The registry checks them in this order, before any
mutation work:

1. **epoch** - a claim whose coordinator epoch is not current fails with
   `StaleEpoch`;
2. **publisher** - an unknown or retired publisher fails with `StaleAuthority`;
   a fenced publisher fails with `FencedPublisher`;
3. **incarnation** - a claim carrying a worker incarnation that is not the one
   currently bound to that publisher fails with `StaleWorkerBoot`;
4. **idempotency** - the exact same already-committed `(publisher, attempt)`
   with an identical request digest returns `Idempotent` and produces **no new
   generation**; the same attempt with different content fails with
   `ConflictingReplay`;
5. **generation** - the compare-and-commit check. At most one authoritative
   commit can occur for a given expected generation, because the check and the
   commit happen inside the same exclusive critical section.

A publisher that restarts receives a freshly minted incarnation. Every
incarnation it previously held is fenced permanently. When a publisher is fenced
- because its session ended, its heartbeat expired, it detached, or the
coordinator epoch advanced - every record whose current evidence came from that
incarnation and was process-bound moves to `RevalidationRequired`, and the
evidence is marked invalid. Durable administrative evidence is preserved.

Idempotent replay is therefore distinguished from stale replay by construction,
not by ordering luck: an exact replay short-circuits before the generation
check, and an old write can never look harmless.

---

## 9. Persistence and recovery

State files are versioned and integrity-checked:

    offset 0    magic[8]            "FABRICRG"
    offset 8    format_version u32  currently 1
    offset 12   reserved u32        must be zero
    offset 16   payload_length u64  exact payload byte count
    offset 24   payload             canonical encoding of the durable state
    offset 24+L integrity[32]       SHA-256 over the payload bytes

The payload opens with the format version again and closes with a `StateDigest`
recomputed from its own records. Loading validates the magic, the format
version, the declared length against the actual file size, the integrity digest,
every per-record length prefix, every enum value, every string bound, the
absence of duplicate canonical identities, duplicate aliases and duplicate
publishers, and the recomputed state digest. Corruption, truncation, impossible
lengths, invalid enums and trailing bytes are all rejected with a specific
stage.

**Replacement is transactional.** The authoritative file is never opened for
writing. A single temporary file `<target>.tmp` in the same directory is
created with create-new semantics, written, flushed to the device, closed, read
back and validated, and only then does it atomically replace the target. If the
process dies at any point before the replacement, the authoritative file still
holds the previous complete state. One writer per state path is required, which
is what the create-new temporary enforces. A leftover temporary file can only
come from a writer that died before replacing; the next load removes it.

**Recovery is conservative.** Loading advances the coordinator epoch, restores
canonical identity and lifecycle, and refuses to restore live authority:

* publishers are restored **fenced**, with a null incarnation; each must
  reattach with a fresh incarnation;
* current records backed by **process-bound** evidence become
  `RevalidationRequired` with invalid evidence;
* current records backed by **durable administrative** evidence stay current;
* record generations are preserved, so a caller holding a generation from
  before the restart still recognizes it;
* traffic from the previous epoch fails with `StaleEpoch`;
* the idempotency log is preserved, so a replay after a restart is still
  recognized as idempotent rather than applied a second time.

Durable identity survives restart. Live authority does not.

---

## 10. Distributed process model

The coordinator and publishers are **real operating-system processes**
communicating over loopback TCP with an explicitly framed protocol. Multiprocess
behaviour is never simulated with threads.

Frame layout (all integers little-endian):

    offset 0    magic[4]         'F','R','G','1'
    offset 4    version u16      1
    offset 6    type u16         MessageType
    offset 8    flags u32        reserved, must be zero
    offset 12   request_id u64   echoed in the response
    offset 20   payload_length u32
    offset 24   payload
    offset 24+L checksum u64     first 8 bytes of SHA-256 over bytes [0, 24+L)

A frame declaring a payload larger than the configured bound is rejected before
any buffer is sized from it. Unknown message types, unknown protocol versions,
non-zero flags, truncated frames and checksum mismatches are each rejected with
their own status. Payload bodies are decoded with bounds-checked readers that
reject trailing bytes: a message that is not exactly consumed is malformed.
There are 27 message types. No C++ object is ever written to the wire.

**Shutdown is bounded by construction.** A blocking `recv` is never relied on
to wake up: every socket read goes through a bounded `select` wait, so a reader
always returns within one poll interval and re-checks its stop flag, and
`request_stop` additionally shuts the socket down. Either mechanism alone
would suffice on a well-behaved platform; together they make the stop path
bounded everywhere, including Windows, where a blocked `recv` is not reliably
woken by `shutdown` alone. Repeated start/stop is exercised 25 times per run in
the test suite, and 200 connect/stop/close cycles are exercised per transport
run.

Session threads never take the session table lock, so the table can always be
locked, inspected and joined from the acceptor, the reaper and `stop`. Session
threads are only ever joined by the reaper or by `stop`, never by themselves.
The registry never calls into a session while holding its lock, and a session
never holds another lock while calling the registry.

---

## 11. Validation provenance: REAL, SYNTHETIC, UNSUPPORTED

These labels are never inferred and never upgraded.

### REAL - exercised against actual state on this machine

The Windows discovery adapter enumerated this host through
`GetAdaptersAddresses`, `GetIfEntry2`, SetupAPI and `GetComputerNameExW`,
producing 16 observations with zero diagnostics: the local host identity; a
Realtek PCIe 5GbE controller (`permanent-mac 10ffe03a9e62`,
`pci-address 0000:0e:00.0`, device instance id); a Qualcomm FastConnect 7800
Wi-Fi 7 adapter (`58cdc97a962b`, `0000:0d:00.0`); three locally administered
Wi-Fi virtual adapters; a Bluetooth PAN adapter; nine Plug-and-Play network
devices that no adapter claimed; and the host record. Loopback TCP transport,
the coordinator, the publisher, persistence and the multiprocess proofs are all
exercised against real operating-system processes on this host.

### SYNTHETIC - exercised with generated records

The identity, lifecycle, authority, reconciliation, persistence, protocol and
adversarial suites use synthetic fixtures for fabric, site, switch, router, NIC,
SmartNIC, DPU, port, link and endpoint records.
`provenance.validity_class` records that; nothing relabels a synthetic switch
fleet as physical network proof.

### UNSUPPORTED - cannot be truthfully provided here

`discovery_capabilities()` reports, with a specific reason for each:
accelerator devices, RDMA devices, physical switches, optical links, and
SmartNIC/DPU enumeration. Fabric Registry can *represent* those identity classes
- the entity classes, fact kinds and lifecycles exist and are tested - but no
claim is made that any of that hardware was enumerated, and no such claim is
made anywhere in this repository.

AddressSanitizer is UNSUPPORTED on this host: the Visual Studio installation has
no "C++ AddressSanitizer" component, so `cl /fsanitize=address` fails to link
(`LNK1104 clang_rt.asan_*.lib`). `FABRIC_REGISTRY_SANITIZERS=ON` therefore
fails at configure time with an explicit message rather than producing a build
that pretends to be instrumented. The strongest available substitute is used
instead: MSVC static analysis (`/analyze /analyze:WX-`) plus Debug builds with
`/RTC1` and `_ITERATOR_DEBUG_LEVEL=2`.

---

## 12. Build

Requirements: CMake 3.20 or newer, a C++20 compiler, and Ninja or another
generator. There are no external dependencies.

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build

CMake options (all default ON, except the last two):

| Option | Effect |
| --- | --- |
| `FABRIC_REGISTRY_BUILD_TESTS` | Build the test executables and register them with CTest |
| `FABRIC_REGISTRY_BUILD_TOOLS` | Build the CLI, coordinator and publisher executables |
| `FABRIC_REGISTRY_BUILD_EXAMPLES` | Build the six examples |
| `FABRIC_REGISTRY_BUILD_BENCHMARKS` | Build the benchmark program |
| `FABRIC_REGISTRY_WARNINGS_AS_ERRORS` | `/W4 /WX` on MSVC, `-Wall -Wextra -Wpedantic -Werror` elsewhere |
| `FABRIC_REGISTRY_SANITIZERS` (OFF) | AddressSanitizer; fails at configure with a clear message when the toolchain has no ASan runtime |
| `FABRIC_REGISTRY_ANALYZE` (OFF) | MSVC static analysis (`/analyze /analyze:WX-`) |

`BUILD_SHARED_LIBS=ON` builds a shared library and the exported target carries
`FABRIC_REGISTRY_USE_SHARED` for consumers. The default is a static library.
All compiler flags are target-based; there are no directory-global flags and no
machine-specific paths.

---

## 13. Test

    cmake --build build
    ctest --test-dir build --output-on-failure

No test uses a timeout. There is no watchdog, no timeout property and no timeout
parameter anywhere in the build or the suite: a deadlock hangs the run and has
to be diagnosed. The suites are:

| Suite | What it proves |
| --- | --- |
| test-ids | Typed identifiers, parsing, canonical renderings, counter overflow, hashing |
| test-digest | SHA-256 against the NIST vectors, an independent in-test reference implementation, every padding boundary (0,1,55,56,57,63,64,65,119,120,127,128,1000), streaming equality, domain separation |
| test-lifecycle | All 81 transition pairs against a hand-written table, outcome classification tables |
| test-frame | Every message type and payload codec, byte-at-a-time decoding, all six rejection classes, trailing-byte and invalid-enum rejection |
| test-persistence | Round trip, generation preservation, corruption and truncation of every field, atomic replacement, temporary-file cleanup |
| test-registry | Registration, idempotency, stale generations, aliases, lifecycle, supersession, conflict resolution, snapshots, epochs, publishers |
| test-reconcile | Every match class, probable/ambiguous/conflicting outcomes, duplicate identity, replacement at a reused location, determinism |
| test-identity-* | Canonicalisation of every fact kind and alias namespace, provenance rules, bounds |
| test-transport | Loopback round trips for all message types, bounded stop with a blocked reader, peer close, repeated start/stop |
| test-concurrency | Deterministic races forced with a barrier, each asserting the legal outcome set and re-validating the indexes |
| test-property | Seeded state-machine drivers that re-check every invariant after every operation, codec round trips with single-byte mutations, monotonicity, replay properties |
| test-adversarial | Malformed identities, oversized input, embedded NUL and invalid UTF-8, locally administered MACs, stale authority of every kind, resource bounds, corrupt state, repeated lifecycle stress |
| test-multiprocess | Real process death, reincarnation, stale incarnation replay, real coordinator death and restart, epoch advance, conservative recovery, crashes during persistence, malformed and abrupt sessions |

---

## 14. Install and consume

    cmake --install build --prefix /path/to/prefix

A downstream project then uses:

    find_package(FabricRegistry CONFIG REQUIRED)
    target_link_libraries(my_app PRIVATE SummonSoftwareLabs::FabricRegistry)

`tests/package_consumer/` is a standalone downstream project used to validate
the installed artifact: it configures against an install prefix, compiles, links
and runs a real registry operation, and it never references the source tree.

---

## 15. Command-line tools

### fabric-registry-cli - inspection

    fabric-registry-cli version
    fabric-registry-cli capabilities
    fabric-registry-cli discover [--json]
    fabric-registry-cli inspect   --state PATH
    fabric-registry-cli validate  --state PATH
    fabric-registry-cli snapshot  --state PATH [--json]
    fabric-registry-cli show      --state PATH --id class:hex
    fabric-registry-cli explain   --state PATH --id class:hex
    fabric-registry-cli resolve   --state PATH --alias namespace:scope=value
    fabric-registry-cli publishers --state PATH

`inspect` reports the recovery outcome, `validate` recomputes every index and
prints a deterministic consistency report, and `explain` prints the lineage
with the reason each generation was produced. Output is deterministic and line
oriented.

### fabric-registry-coordinator

    fabric-registry-coordinator --listen 127.0.0.1:0 --state PATH [--ready-file PATH]
                                [--run-ms N] [--no-persist] [--quiet]

It recovers durable state at start (and refuses to start on a corrupt state file
rather than silently starting empty), serves the protocol, and writes the final
state on a bounded, graceful stop. A failed durable write is reported on
standard error and counted; it is never swallowed.

### fabric-registry-publisher

    fabric-registry-publisher --mode attach --coordinator HOST:PORT --name NAME
                              [--count N] [--serial-prefix P] [--evidence durable|process-bound]
                              [--revalidate ID]... [--hold-ms N] [--detach] [--report PATH]
    fabric-registry-publisher --mode replay --coordinator HOST:PORT
                              --publisher HEX --boot HEX --epoch N

`replay` sends one mutation carrying an explicitly supplied authority claim
without attaching. It is how the multiprocess proof replays traffic from a
fenced incarnation. The report file is republished at every stage, so a
supervisor never has to wait for the process to exit.

---

## 16. Examples

| Program | What it shows |
| --- | --- |
| `examples/01_basic_registration.cpp` | Derived canonical identity, lookup, deterministic re-derivation |
| `examples/02_alias_resolution.cpp` | Fabric-scoped alias resolution, informational aliases, namespace scoping |
| `examples/03_idempotency_and_conflicts.cpp` | Idempotent replay, conflicting replay, stale generation |
| `examples/04_lifecycle_and_supersession.cpp` | Supersession, non-resurrection, retirement, tombstone, lineage |
| `examples/05_persistence_and_recovery.cpp` | Durable identity survives, process-bound authority does not |
| `examples/06_distributed_publisher.cpp` | A real coordinator session over loopback TCP |

---

## 17. Benchmarks

`fabric-registry-benchmarks` measures **completed** operations, never enqueue
latency. `--quick` runs only the 1k sizes; `--json` prints one JSON object
per measurement. The 100k sizes are compiled out of Debug builds. Every workload
runs a warmup pass and prints the measured count next to the rate.

Measured on this host, MSVC 19.44 x64, Release, whole-second wall clock:

| Workload | Count | Seconds | Completed ops/s |
| --- | --- | --- | --- |
| register bulk, 1k entities | 1000 | 0.005 | 1.86e+05 |
| register bulk, 10k entities | 10000 | 0.065 | 1.53e+05 |
| register bulk, 100k entities | 100000 | 0.780 | 1.28e+05 |
| register incremental at 1k / 10k / 100k | 1000 each | 0.005 / 0.007 / 0.007 | 1.82e+05 / 1.52e+05 / 1.50e+05 |
| lookup by canonical identity at 1k / 10k / 100k | 100000 each | 0.004 / 0.008 / 0.021 | 2.28e+07 / 1.23e+07 / 4.69e+06 |
| lookup by alias at 1k / 10k / 100k | 100000 each | 0.026 / 0.036 / 0.058 | 3.79e+06 / 2.80e+06 / 1.72e+06 |
| reconciliation lookup at 1k / 10k / 100k | 20000 each | 0.056 / 0.081 / 0.071 | 3.55e+05 / 2.47e+05 / 2.80e+05 |
| snapshot construction at 1k / 10k / 100k | 200 / 20 / 2 | 0.353 / 0.559 / 0.788 | 567 / 35.8 / 2.54 |
| persistence save at 1k / 10k | 5 each | 0.077 / 0.443 | 65.2 / 11.3 |
| persistence load at 1k / 10k | 5 each | 0.040 / 0.558 | 125 / 8.96 |

These are descriptive, not targets. Snapshot construction is deliberately O(n):
a snapshot is an immutable, self-consistent copy with its own state digest.

---

## 18. Thread safety, ownership and lifetimes

One `Registry` may be shared by any number of threads. Reads take a shared
lock; mutations take an exclusive lock. Records are immutable once committed and
are held by `std::shared_ptr`, so a value returned by a read stays valid and
unchanged forever, independently of later mutations. The library never invokes a
caller-supplied callback while holding its lock, and never returns a reference
into guarded state. The only caller-supplied callback is the optional entropy
source, which is invoked during identifier minting and never re-enters the
registry.

`Registry` is neither copyable nor movable and is the sole owner of its mutable
state; the objects it hands out - `Snapshot`,
`std::shared_ptr<const EntityRecord>`, `PublisherRecord` copies - are
independent values whose lifetime is not tied to the registry. `Coordinator`
and `PublisherClient` own their threads and connections; `Coordinator::stop`
is idempotent and must not be called from a session thread.

Indexes are maintained incrementally; no index is rebuilt on a mutation.
`Registry::validate_state` recomputes every index from the record table and
compares it, and the test suite calls it after every operation in the property
driver.

---

## 19. Limitations

* The identity model is deliberately conservative: a probable match never
  commits. A caller that wants to accept weak evidence must say so explicitly.
* `resolve_conflict` is administrative: it moves a conflicted record to
  current, retired or rejected. It does not adjudicate between two competing
  hardware claims on the caller's behalf.
* The persisted state is a single file with a single writer. There is no
  replication, no consensus and no multi-writer coordination.
* Key material is not used to authenticate peers. Authority is bound to a
  publisher incarnation and an epoch on a trusted loopback control path; running
  the coordinator on an untrusted network requires an authenticating transport.
* Only the local host can be enumerated. Physical switches, RDMA, optical links,
  SmartNIC/DPU management and accelerator correlation are reported as
  UNSUPPORTED, not approximated.
* AddressSanitizer is unavailable on this host (see section 11). Static analysis
  and Debug runtime checks are used instead.
* Snapshots copy `shared_ptr`s, which is cheap, but the accompanying state
  digest is computed over every record, so taking a snapshot of a very large
  registry is O(n). The measured cost is in section 17.

---

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
