# ChordAuditMatrixBench

Benchmark framework and executables for **ChordAuditMatrix** — PDP audit and identity verification performance testing.

## Overview

This repository provides three standalone benchmark executables:

| Executable | Description |
|---|---|
| `PdpChordAuditMatrixBench` | PDP (Provable Data Possession) audit benchmark — measures detection confidence rate vs. theoretical hypergeometric probability |
| `IdentityChordAuditMatrixBench` | Identity verification benchmark — measures verification accuracy rate (TP/FP/TN/FN) |
| `DynamicMaintenanceChordAuditMatrixBench` | Dynamic PDP maintenance benchmark — measures Update/Insert/Delete call latency and success/failure totals |

The PDP and identity executables support single-run and parameter-sweep modes.
The maintenance executable is single-run: one maintenance call per iteration,
partitioned across workers.

## Build Modes

### Standalone (default: `CAM_STANDALONE=ON`)

Builds as an independent project. `ChordAuditMatrixLib` (CoreLib) is statically compiled via `3rdparty/CoreLib` submodule. Produces self-contained binaries.

```bash
git clone --recursive git@github.com:ChordAuditMatrix/ChordAuditMatrixBench.git
cd ChordAuditMatrixBench
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

The framework unit tests (MetricsCollector aggregation, run scheduling, the
shared stage timer, the Report hierarchy, Scenario defaults) build with
`CAM_BUILD_TESTS=ON` and run under CTest in the same build tree:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCAM_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Tests that need the real `DHTDynamicAuditStrategy` / `SM9StaticAuditStrategy`
plugins stay in the parent ChordAuditMatrix repository, which is where those
submodules live.

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

### Dynamic Maintenance Benchmark

```
--algorithm <type>          Dynamic strategy type (default: DHTDynamic)
--strategy-path <dir>       Strategy library directory for hot-loading
--operation <type>          update | insert | delete (default: update)
--initial-blocks <N>        Blocks pre-filled in each worker's StateStore
                            (default: 1000; delete needs N >= the largest
                            worker's iteration share)
--iterations <N>            Total maintenance calls across all workers
--threads <N>               Worker count (0 = hardware concurrency)
--seed <N>                  Seed the benchmark PRNG (index selection is
                            deterministic; accepted for CLI parity)
--json <path>               Write JSON report to file
--help                      Show help message
```

Iteration semantics — exactly one maintenance call per iteration, on legal
1-based block indices of the worker's own store:

- **Update** — round-robin over the initial blocks (`1..initialBlocks`);
- **Insert** — append at the current block count + 1;
- **Delete** — drop the current last block, consuming the store tail-first.

Each worker creates its own engine, operation context and StateStore from the
shared dynamic strategy, so iterations are independent and partition across
`--threads`. A rejected operation is counted as a failure (exit code 2), not
thrown. Delete configs whose `--initial-blocks` cannot cover the largest
worker's share are rejected up front (exit code 1).

Reported metrics: per-operation success/failure totals, the final block count
summed over all worker stores (Update keeps it at `initialBlocks × threads`,
Insert adds one per successful insert, Delete removes one per successful
delete), total and average maintenance call time (aggregated across workers),
setup timings, end-to-end wall time and an end-to-end throughput whose
denominator is the whole run (setup + iterations + teardown). Maintenance benchmarking lives in this
executable only — PDP audit iterations never run maintenance.

### Online Identity Algorithms (session-coordinated)

Algorithms whose `kind() == Online` (derived from
`OnlineIdentitySigningAlgorithm`, e.g. `SM9Online`) carry a coordinator-issued
session string through the common identity signing and aggregation operations:

- **Session strings** — generated internally for every sample and iteration
  from a random canonical UUID-v4-like 36-character session ID and the
  `"IdentityVerify"` context; no new CLI parameter is introduced. Each
  single-signature sample signs under its own session string.
- **Aggregate scenario** — automatically enabled when `--num-users >= 2`.
  The signer count reuses `--num-users`; each sample contains n registered
  signers using one shared session string, then uses the common
  `aggregate(AggregateRequest)` operation and is aggregate-verified.
- **Sample kinds** — legal, forged signature, tampered message, and
  impersonated identity. Negative-sample ratios are controlled by the existing
  `--forgery-ratio`, `--tampered-ratio`, and `--impersonation-ratio` options.
- **Metrics** — setup and iteration timing metrics expose total, average, and
  call-count values. Identity communication metrics cover KGC-issued private
  keys, individual signatures, and aggregate signatures sent for verification;
  local aggregation has no communication metric.

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
│   ├── benchmark_computation_strategy.h
│   ├── benchmark_config.h
│   ├── benchmark_report.h
│   ├── benchmark_runner.h
│   ├── benchmark_scenario.h
│   ├── benchmark_timing.h
│   ├── benchmark_types.h
│   ├── dynamic_maintenance_report.h
│   ├── dynamic_maintenance_scenario.h
│   ├── metrics_collector.h
│   ├── pdp_audit_scenario.h
│   └── identity_verify_scenario.h
├── source/
│   ├── pdp_audit_scenario.cpp
│   ├── dynamic_maintenance_scenario.cpp
│   ├── dynamic_maintenance_report.cpp
│   ├── benchmark_report.cpp
│   ├── benchmark_computation_strategy.cpp
│   └── identity_verify_scenario.cpp
├── tests/                    (CAM_BUILD_TESTS=ON framework unit tests)
└── app/
    ├── pdp_audit_benchmark_main.cpp
    ├── dynamic_maintenance_benchmark_main.cpp
    └── identity_verify_benchmark_main.cpp
```

## License

GPL-3.0-or-later — see [LICENSE](LICENSE).