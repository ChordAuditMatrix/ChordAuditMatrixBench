# ChordAuditMatrixBench

Benchmark framework and executables for **ChordAuditMatrix** — PDP audit and identity verification performance testing.

## Overview

This repository provides two standalone benchmark executables:

| Executable | Description |
|---|---|
| `PdpChordAuditMatrixBench` | PDP (Provable Data Possession) audit benchmark — measures detection confidence rate vs. theoretical hypergeometric probability |
| `IdentityChordAuditMatrixBench` | Identity verification benchmark — measures verification accuracy rate (TP/FP/TN/FN) |

Both executables support single-run and parameter-sweep modes.

## Build Modes

### Standalone (default: `CAM_STANDALONE=ON`)

Builds as an independent project. `ChordAuditMatrixLib` (CoreLib) is statically compiled via `3rdparty/CoreLib` submodule. Produces self-contained binaries.

```bash
git clone --recursive git@github.com:ChordAuditMatrix/ChordAuditMatrixBench.git
cd ChordAuditMatrixBench
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

### In-tree (`CAM_STANDALONE=OFF`)

Used when included as a submodule of the main ChordAuditMatrix project. `ChordAuditMatrixLib` target already exists; benchmarks are deployed to `dist/bench/`.

```cmake
# In parent CMakeLists.txt:
set(CAM_STANDALONE OFF CACHE BOOL "Submodules: build in-tree" FORCE)
add_subdirectory(3rdparty/ChordAuditMatrixBench EXCLUDE_FROM_ALL)
```

## CLI Parameters

### PDP Audit Benchmark

```
--algorithm <type>          Algorithm type (SM9Static | DHTDynamic)
--strategy-path <dir>       Strategy library directory for hot-loading
--iterations <N>            Iterations per parameter combo (default: 10)
--total-blocks <N>          Total data blocks N (default: 1000)
--corrupted-blocks <N>      Corrupted blocks t (default: 10)
--sample-size <N>           Sample size r per audit (default: 50)
--sweep                     Enable parameter sweep mode
--sweep-mode <mode>         Sweep mode: fixedN (default) or fixedRatio
--json <path>               Write JSON report to file
--list-algorithms           List available algorithms and exit
--help                      Show help message
```

### Identity Verification Benchmark

```
--algorithm <type>          Algorithm type (SM9Noncert)
--iterations <N>            Iterations per parameter combo (default: 10)
--num-users <N>             Number of participating users (default: 10)
--samples-per-iter <N>      Samples verified per iteration (default: 20)
--forgery-ratio <r>         Forgery negative sample ratio (default: 0.25)
--tampered-ratio <r>        Tampered message negative sample ratio (default: 0.25)
--impersonation-ratio <r>   Impersonation negative sample ratio (default: 0.25)
--sweep                     Enable parameter sweep (scan user counts)
--json <path>               Write JSON report to file
--list-algorithms           List available identity algorithms and exit
--help                      Show help message
```

### Online Identity Algorithms (session-coordinated)

Algorithms whose `kind() == Online` (derived from
`OnlineIdentitySigningAlgorithm`, e.g. `SM9Online`) are driven through the
session-coordinated path in addition to the offline single-signature path:

- **Session strings** — generated internally per sample via
  `makeSessionString("bench-" + counter, "IdentityVerify")`; the session id
  comes from an internal incrementing counter, so **no new CLI parameter** is
  introduced. Each single-signature sample signs under its own session string
  (embedded in the `ONS` signature, self-contained at verification time).
- **Aggregate scenario** — automatically enabled when the algorithm is Online
  **and** `--num-users >= 2` (the signer count reuses `--num-users`). Each
  aggregate sample has n = `--num-users` distinct signers signing distinct
  messages under **one shared session string**, then aggregated via
  `aggregateSessionSignatures` and verified via `aggregateVerify` (`ONA`).
- **Sample kinds (per n, equal legal vs tampered counts)**:
  - Legal aggregate → accept (TP);
  - Tampered: one byte flipped inside the aggregate signature bytes → reject (TN);
  - Tampered: one signer entry removed from the `ONA` roster → reject (TN);
  - Cross-session mixing (signatures from two session strings fed to the
    aggregator) → aggregation rejected, counted in `rejectedAggregation`
    (never a TP/FP);
  - Duplicate signer (same session + userId signs twice) → aggregation
    rejected, counted in `rejectedAggregation`.
- **New metrics** — the aggregation stage timing (`aggregateMs`) and the
  aggregate signature bytes (`aggregateSignatureBytes`, `ONA` roster grows
  O(n) with the signer count) are collected per iteration and reported
  alongside the existing four-stage timings; the report also carries
  `algorithmKind` (`Online`/`Offline`) and `aggregateSigners` (n; 0 when off).

See the design docs (Doc 4: ChordAuditMatrixBenchmark完善文档.md §2/§3) for the
exact sample construction and accuracy accounting rules.

## Repository Structure

```
ChordAuditMatrixBench/
├── CMakeLists.txt
├── LICENSE
├── README.md
├── .gitmodules
├── .github/workflows/ci.yml
├── 3rdparty/CoreLib/          (git submodule)
├── include/ChordAuditMatrixBench/
│   ├── benchmark_config.h
│   ├── benchmark_report.h
│   ├── benchmark_runner.h
│   ├── benchmark_scenario.h
│   ├── benchmark_types.h
│   ├── metrics_collector.h
│   ├── pdp_audit_scenario.h
│   └── identity_verify_scenario.h
├── source/
│   ├── pdp_audit_scenario.cpp
│   └── identity_verify_scenario.cpp
└── app/
    ├── pdp_audit_benchmark_main.cpp
    └── identity_verify_benchmark_main.cpp
```

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).