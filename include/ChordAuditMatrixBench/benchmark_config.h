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
 * @brief Framework-level sequence resolution utilities
 * @details Provides resolveSeq() — the single shared helper used by all
 *          ComputationStrategy::parseAndExpand() implementations to turn a
 *          SeqSpec (explicit list / linear / geometric) into a concrete list
 *          of sweep points. Per-strategy parameter parsing now lives in each
 *          strategy's parseAndExpand(); theoreticalConfidenceRate() and the
 *          legacy expandSweep()/default*Sweep() helpers have been removed.
 * @author Dylan Liu
 * @version 4.0.0
 * @date 2026-07-22
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
 * @brief Resolve a sequence axis into a concrete list of values
 * @details If spec.gen is Explicit, the explicitVals list is used verbatim.
 *          Otherwise a Linear or Geometric sequence is generated from
 *          start/end/step/ratio, capped at spec.maxPoints.
 * @param explicitVals Values to use verbatim when spec.gen == SweepGen::Explicit
 * @param spec SeqSpec describing how to generate the sequence
 * @return Concrete list of values for the axis
 */
inline std::vector<std::size_t> resolveSeq(const std::vector<std::size_t>& explicitVals,
                                            const SeqSpec& spec)
{
    // Explicit mode: use the provided list verbatim
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
        double v = static_cast<double>(spec.start);
        while (v <= static_cast<double>(spec.end) && out.size() < spec.maxPoints) {
            out.push_back(static_cast<std::size_t>(std::llround(v)));
            std::size_t nextVal = static_cast<std::size_t>(std::llround(v * spec.ratio));
            if (nextVal <= out.back()) break;
            v *= spec.ratio;
        }
    }
    return out;
}

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_CONFIG_H
