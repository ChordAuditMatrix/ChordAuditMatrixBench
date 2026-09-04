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
 * @file dynamic_strategy_execution_coordinator.h
 * @brief Coordinator for worker-local StateStore access through a shared dynamic strategy
 * @details Serializes each StateStore binding together with the complete
 *          StateStore-dependent operation, preventing another benchmark worker
 *          from replacing the shared strategy's active store mid-operation.
 * @author Dylan Liu
 * @version 1.0.0
 * @date 2026-09-05
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_DYNAMIC_STRATEGY_EXECUTION_COORDINATOR_H
#define CAMATRIX_AUDIT_BENCHMARK_DYNAMIC_STRATEGY_EXECUTION_COORDINATOR_H

#include "ChordAuditMatrixLib/interfaces/audit/dynamic_strategy.h"

#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace CAMatrix::Audit::Benchmark {

/**
 * @class DynamicStrategyExecutionCoordinator
 * @brief Serializes StateStore-dependent operations on a shared dynamic strategy
 * @details Each benchmark worker owns its StateStore. execute() keeps binding that
 *          store and the complete dependent operation in one critical section, so
 *          another worker cannot replace the strategy's StateStore mid-operation.
 */
class DynamicStrategyExecutionCoordinator {
public:
    using DynamicStrategy = CAMatrix::Audit::Core::DynamicAuditStrategy;
    using StateStore = CAMatrix::Audit::Core::DynamicPdpStateStore;

    /**
     * @brief Construct a coordinator for one shared dynamic strategy
     * @param strategy Dynamic strategy shared by all coordinated benchmark workers
     * @throws std::invalid_argument If strategy is nullptr
     */
    explicit DynamicStrategyExecutionCoordinator(
        std::shared_ptr<DynamicStrategy> strategy)
        : strategy_(std::move(strategy))
    {
        if (!strategy_) {
            throw std::invalid_argument(
                "DynamicStrategyExecutionCoordinator: strategy must not be null");
        }
    }

    DynamicStrategyExecutionCoordinator(
        const DynamicStrategyExecutionCoordinator&) = delete;
    DynamicStrategyExecutionCoordinator& operator=(
        const DynamicStrategyExecutionCoordinator&) = delete;

    /**
     * @brief Execute one complete StateStore-dependent operation
     * @param stateStore Store owned by the calling worker scenario
     * @param operation Operation that must observe that store throughout its call
     */
    template<typename Operation>
    decltype(auto) execute(
        const std::shared_ptr<StateStore>& stateStore,
        Operation&& operation)
    {
        if (!stateStore) {
            throw std::invalid_argument(
                "DynamicStrategyExecutionCoordinator: stateStore must not be null");
        }

        std::lock_guard<std::mutex> lock(mutex_);
        strategy_->setStateStore(stateStore);
        return std::forward<Operation>(operation)();
    }

    /**
     * @brief Check whether the coordinator owns the supplied strategy instance
     * @param strategy Dynamic strategy instance to compare
     * @return true when strategy is the coordinated instance
     */
    bool coordinates(const std::shared_ptr<DynamicStrategy>& strategy) const noexcept
    {
        return strategy_.get() == strategy.get();
    }

private:
    std::shared_ptr<DynamicStrategy> strategy_;
    std::mutex mutex_;
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_DYNAMIC_STRATEGY_EXECUTION_COORDINATOR_H
