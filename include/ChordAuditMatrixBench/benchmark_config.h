/*
 * Copyright (C) 2021-2026, Dylan Liu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file benchmark_config.h
 * @brief Configuration utilities for the audit benchmark framework
 * @details Provides factory functions for creating common parameter sweep
 *          configurations and helpers for expanding sweeps into individual
 *          BenchmarkConfig instances. Supports both PDP audit and identity
 *          verification sweep modes, with dynamic PDP field propagation.
 * @author Dylan Liu
 * @version 3.0.0
 * @date 2026-07-08
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_CONFIG_H
#define CAMATRIX_AUDIT_BENCHMARK_CONFIG_H

#include <ChordAuditMatrixBench/benchmark_types.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

/**
 * @brief Compute the theoretical audit confidence rate using hypergeometric distribution
 * @details For N total blocks with t corrupted, sampling r blocks without replacement,
 *          the probability of detecting at least one corrupted block is:
 *          P = 1 - C(N-t, r) / C(N, r) = 1 - prod_{i=0}^{r-1} (N-t-i) / (N-i)
 * @param totalBlocks N: total number of data blocks
 * @param corruptedBlocks t: number of corrupted blocks
 * @param sampleSize r: number of blocks sampled per audit
 * @return Theoretical confidence rate in [0, 1]
 */
inline double theoreticalConfidenceRate(std::size_t totalBlocks,
                                         std::size_t corruptedBlocks,
                                         std::size_t sampleSize)
{
    // Edge cases
    if (totalBlocks == 0 || sampleSize == 0 || corruptedBlocks == 0) return 0.0;
    if (corruptedBlocks >= totalBlocks) return 1.0;  // All blocks corrupted
    if (sampleSize >= totalBlocks) return 1.0;        // Sampling all blocks
    if (sampleSize > totalBlocks - corruptedBlocks) return 1.0; // Must sample at least one corrupted

    // P(detect) = 1 - prod_{i=0}^{r-1} (N-t-i) / (N-i)
    // Use log-space to avoid numerical overflow for large N
    double logRatio = 0.0;
    for (std::size_t i = 0; i < sampleSize; ++i) {
        double numerator = static_cast<double>(totalBlocks - corruptedBlocks - i);
        double denominator = static_cast<double>(totalBlocks - i);
        if (numerator <= 0.0) return 1.0; // Must have sampled a corrupted block
        logRatio += std::log(numerator) - std::log(denominator);
    }
    return 1.0 - std::exp(logRatio);
}

/**
 * @brief Resolve a sequence axis into a concrete list of values
 * @details If spec.gen is Explicit, the explicitVals list is used verbatim
 *          (backward compatible). Otherwise a Linear or Geometric sequence is
 *          generated from start/end/step/ratio, capped at spec.maxPoints.
 * @param explicitVals Values to use verbatim when spec.gen == SweepGen::Explicit
 * @param spec SeqSpec describing how to generate the sequence
 * @return Concrete list of values for the axis
 */
inline std::vector<std::size_t> resolveSeq(const std::vector<std::size_t>& explicitVals,
                                            const SeqSpec& spec)
{
    // Explicit mode: use the provided list verbatim (backward compatible)
    if (spec.gen == SweepGen::Explicit) {
        return explicitVals;
    }

    // Generator modes require valid bounds
    if (spec.step == 0 && spec.gen == SweepGen::Linear) {
        return {}; // step=0 is illegal for Linear (would loop forever)
    }
    if (spec.ratio <= 1.0 && spec.gen == SweepGen::Geometric) {
        return {}; // ratio<=1.0 is illegal for Geometric (would not progress)
    }
    if (spec.end < spec.start) {
        return {}; // empty range
    }

    std::vector<std::size_t> out;
    out.reserve(64);

    if (spec.gen == SweepGen::Linear) {
        for (std::size_t v = spec.start;
             v <= spec.end && out.size() < spec.maxPoints;
             v += spec.step) {
            out.push_back(v);
        }
    } else { // Geometric
        // Use double accumulator to avoid integer overflow on early iterations;
        // round to nearest size_t when pushing. Stop when value exceeds end or
        // when we hit maxPoints (safety cap).
        double v = static_cast<double>(spec.start);
        while (v <= static_cast<double>(spec.end) && out.size() < spec.maxPoints) {
            out.push_back(static_cast<std::size_t>(std::llround(v)));
            // Guard against ratio producing a non-progressing sequence due to
            // rounding (v rounds to same integer twice) — break if stuck.
            std::size_t nextVal = static_cast<std::size_t>(std::llround(v * spec.ratio));
            if (nextVal <= out.back()) break;
            v *= spec.ratio;
        }
    }
    return out;
}

/**
 * @brief Expand a ParameterSweep into a list of individual BenchmarkConfig instances
 * @details For PDP audit modes (FixedN_ScanTR, FixedRatio_ScanN), generates configs
 *          with PDP-specific fields populated. For Identity_ScanUsers mode, generates
 *          configs with identity verification fields (numUsers, samplesPerIteration,
 *          negativeSamples) populated.
 *
 *          Each swept axis (t, r, N, users) is resolved via resolveSeq(): if the
 *          axis SeqSpec.gen is Explicit, the corresponding *Values vector is used
 *          verbatim; otherwise a Linear or Geometric sequence is generated from
 *          start/end/step/ratio. This preserves full backward compatibility —
 *          default SeqSpec is Explicit, so existing code paths that fill *Values
 *          are unchanged.
 * @param sweep Parameter sweep configuration
 * @return Vector of BenchmarkConfig, one per parameter combination
 */
inline std::vector<BenchmarkConfig> expandSweep(const ParameterSweep& sweep)
{
    std::vector<BenchmarkConfig> configs;

    // Resolve each swept axis: explicit list takes precedence when gen==Explicit,
    // otherwise generate from SeqSpec (Linear / Geometric).
    auto tVals     = resolveSeq(sweep.tValues, sweep.tSpec);
    auto rVals     = resolveSeq(sweep.rValues, sweep.rSpec);
    auto nVals     = resolveSeq(sweep.nValues, sweep.nSpec);
    auto userVals  = resolveSeq(sweep.userValues, sweep.userSpec);

    if (sweep.mode == SweepMode::FixedN_ScanTR) {
        for (auto t : tVals) {
            for (auto r : rVals) {
                BenchmarkConfig cfg;
                cfg.totalBlocks = sweep.fixedN;
                cfg.corruptedBlocks = t;
                cfg.sampleSize = r;
                cfg.iterations = sweep.iterations;
                cfg.usePseudoRandom = sweep.usePseudoRandom;
                cfg.seed = sweep.seed;
                cfg.blockSize = sweep.blockSize;
                // Propagate identity fields for cross-scenario compatibility
                cfg.samplesPerIteration = sweep.samplesPerIteration;
                cfg.negativeSamples = sweep.negativeSamples;
                // Propagate dynamic PDP fields
                cfg.maintenanceOps = sweep.maintenanceOps;
                configs.push_back(cfg);
            }
        }
    } else if (sweep.mode == SweepMode::FixedRatio_ScanN) {
        for (auto n : nVals) {
            BenchmarkConfig cfg;
            cfg.totalBlocks = n;
            cfg.corruptedBlocks = static_cast<std::size_t>(n * sweep.corruptedRatio);
            cfg.sampleSize = static_cast<std::size_t>(n * sweep.sampleRatio);
            // Ensure at least 1 corrupted block and 1 sample
            cfg.corruptedBlocks = std::max<std::size_t>(1, cfg.corruptedBlocks);
            cfg.sampleSize = std::max<std::size_t>(1, cfg.sampleSize);
            // sampleSize cannot exceed totalBlocks
            cfg.sampleSize = std::min(cfg.sampleSize, cfg.totalBlocks);
            // corruptedBlocks cannot exceed totalBlocks
            cfg.corruptedBlocks = std::min(cfg.corruptedBlocks, cfg.totalBlocks);
            cfg.iterations = sweep.iterations;
            cfg.usePseudoRandom = sweep.usePseudoRandom;
            cfg.seed = sweep.seed;
            cfg.blockSize = sweep.blockSize;
            // Propagate identity fields for cross-scenario compatibility
            cfg.samplesPerIteration = sweep.samplesPerIteration;
            cfg.negativeSamples = sweep.negativeSamples;
            // Propagate dynamic PDP fields
            cfg.maintenanceOps = sweep.maintenanceOps;
            configs.push_back(cfg);
        }
    } else { // Identity_ScanUsers
        for (auto numUsers : userVals) {
            BenchmarkConfig cfg;
            cfg.numUsers = numUsers;
            cfg.samplesPerIteration = sweep.samplesPerIteration;
            cfg.negativeSamples = sweep.negativeSamples;
            cfg.iterations = sweep.iterations;
            cfg.usePseudoRandom = sweep.usePseudoRandom;
            cfg.seed = sweep.seed;
            // Propagate PDP fields for cross-scenario compatibility
            cfg.blockSize = sweep.blockSize;
            // Propagate dynamic PDP fields
            cfg.maintenanceOps = sweep.maintenanceOps;
            configs.push_back(cfg);
        }
    }

    return configs;
}

/**
 * @brief Create a default FixedN_ScanTR sweep for typical audit scenarios
 * @param iterations Number of iterations per parameter combination (default: 100)
 * @return ParameterSweep with reasonable defaults
 */
inline ParameterSweep defaultFixedNSweep(std::size_t iterations = 100)
{
    ParameterSweep sweep;
    sweep.mode = SweepMode::FixedN_ScanTR;
    sweep.fixedN = 1000;
    sweep.tValues = {1, 5, 10, 50, 100};
    sweep.rValues = {10, 50, 100, 200};
    sweep.iterations = iterations;
    sweep.blockSize = 256;
    return sweep;
}

/**
 * @brief Create a default FixedRatio_ScanN sweep for scaling analysis
 * @param iterations Number of iterations per parameter combination (default: 100)
 * @return ParameterSweep with reasonable defaults
 */
inline ParameterSweep defaultFixedRatioSweep(std::size_t iterations = 100)
{
    ParameterSweep sweep;
    sweep.mode = SweepMode::FixedRatio_ScanN;
    sweep.corruptedRatio = 0.01;
    sweep.sampleRatio = 0.05;
    sweep.nValues = {100, 500, 1000, 5000, 10000};
    sweep.iterations = iterations;
    sweep.blockSize = 256;
    return sweep;
}

/**
 * @brief Create a default Identity_ScanUsers sweep for identity verification scaling
 * @details Sweeps user counts from small to large with fixed samples per iteration.
 *          Default negative sample ratios: 25% forgery, 25% tampered, 25% impersonation,
 *          leaving 25% positive samples.
 * @param iterations Number of iterations per parameter combination (default: 100)
 * @param samplesPerIteration Number of verification samples per iteration (default: 100)
 * @return ParameterSweep configured for identity verification user scaling
 */
inline ParameterSweep defaultIdentitySweep(std::size_t iterations = 100,
                                            std::size_t samplesPerIteration = 100)
{
    ParameterSweep sweep;
    sweep.mode = SweepMode::Identity_ScanUsers;
    sweep.userValues = {5, 10, 20, 50, 100};
    sweep.samplesPerIteration = samplesPerIteration;
    sweep.negativeSamples = NegativeSampleConfig{}; // default ratios: 0.25/0.25/0.25
    sweep.iterations = iterations;
    return sweep;
}

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_CONFIG_H
