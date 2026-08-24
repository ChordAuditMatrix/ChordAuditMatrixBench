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
 * @file identity_verify_scenario.h
 * @brief Identity verification benchmark scenario — concrete class
 * @details Implements BenchmarkScenario for identity verification algorithms
 *          (e.g., SM9Noncert, SM9Online). The core metric is verification
 *          accuracy rate, measured against a labeled test sample set
 *          containing both positive (legitimate signatures) and negative
 *          (forged, tampered, impersonated) samples.
 *
 *          Online algorithms (derived from
 *          OnlineIdentitySigningAlgorithm) additionally exercise the
 *          session-coordinated aggregation path: setup() derives one session
 *          string per single-signature sample and one shared session string
 *          per aggregate sample (n = numUsers signers); runIteration()
 *          re-aggregates per-signer signatures (measuring aggregateMs and
 *          aggregateSignatureBytes) and aggregate-verifies legal and tampered
 *          samples. Cross-session mixing and duplicate-signer aggregation
 *          rejections are counted separately (rejectedAggregation) and never
 *          enter the TP/FP/TN/FN confusion matrix.
 *
 *          Pipeline:
 *          1. setup(): kind dispatch (Online/Offline) → create manager →
 *             generate master key → derive user keys → generate single-signature
 *             test samples (sign + label) + online aggregate samples
 *          2. runIteration(): loop over test samples → aggregateVerify each;
 *             online: aggregate + verify aggregate samples → count
 *             TP/FP/TN/FN + rejectedAggregation → compute accuracy rate
 *
 * @author Dylan Liu
 * @version 2.1.0
 * @date 2026-08-25
 */

#ifndef CAMATRIX_AUDIT_BENCHMARK_IDENTITY_VERIFY_SCENARIO_H
#define CAMATRIX_AUDIT_BENCHMARK_IDENTITY_VERIFY_SCENARIO_H

#include <ChordAuditMatrixBench/benchmark_scenario.h>
#include <ChordAuditMatrixBench/benchmark_types.h>
#include <ChordAuditMatrixBench/metrics_collector.h>

#include "ChordAuditMatrixLib/interfaces/crypto/types/data.h"
#include "ChordAuditMatrixLib/interfaces/identity/identity_algorithm_manager.h"
#include "ChordAuditMatrixLib/interfaces/identity/identity_algorithm_params.h"
#include "ChordAuditMatrixLib/interfaces/identity/identity_request.h"
#include "ChordAuditMatrixLib/interfaces/identity/online_identity_signing_algorithm.h"

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

// ==================================================================
// Identity sample label
// ==================================================================

/**
 * @struct IdentitySampleLabel
 * @brief A single test sample with ground-truth label for identity verification
 * @details Contains a (message, signature, userId) triple and the expected
 *          verification outcome. Positive samples have shouldAccept=true
 *          (legitimate signature), negative samples have shouldAccept=false
 *          (forged, tampered, or impersonated).
 */
struct IdentitySampleLabel {
    std::string message;                        ///< Original message (hex string)
    CAMatrix::Crypto::CryptoArray signature;     ///< Raw signature bytes (may be forged)
    std::string userId;                         ///< Claimed user identity
    bool shouldAccept;                          ///< Ground truth: should the signature be accepted?
};

// ==================================================================
// Online aggregate sample (session-coordinated, n = numUsers signers)
// ==================================================================

/**
 * @enum AggregateTamperMode
 * @brief Construction mode of an online aggregate verification sample
 * @details Online aggregate samples exercise the session-coordinated
 *          aggregation path (OnlineIdentitySigningAlgorithm::
 *          aggregateSessionSignatures). Verify-path samples (None / FlipByte /
 *          RemoveEntry) enter the TP/FP/TN/FN confusion matrix; aggregation
 *          rejection samples (CrossSession / DuplicateSigner) are counted
 *          separately as rejected aggregations and never enter the matrix.
 */
enum class AggregateTamperMode : std::uint8_t {
    None,           ///< Legal: n distinct signers under one session → expect accept (TP)
    FlipByte,       ///< Legal aggregation, then one byte flipped inside the aggregate bytes → expect reject (TN)
    RemoveEntry,    ///< Legal aggregation, then one signer entry removed from the ONA roster → expect reject (TN)
    CrossSession,   ///< n-1 signers under one session + 1 under another → aggregation must reject (rejectedAggregation)
    DuplicateSigner ///< Same (session, userId) signs twice → aggregation must reject (rejectedAggregation)
};

/**
 * @struct IdentityAggregateSample
 * @brief A single online aggregate verification sample
 * @details Holds the n = numUsers per-signer (userId, message, signature)
 *          triples produced under one shared session string, plus the tamper
 *          mode deciding the expected outcome. Per-signer signatures are
 *          aggregated at runIteration() time so the aggregation stage
 *          (aggregateMs) is measured per iteration.
 */
struct IdentityAggregateSample {
    std::string sessionString;                            ///< Session string shared by all signers (aggregation input)
    std::string sessionString2;                           ///< Second session string (CrossSession only)
    std::vector<std::string> userIds;                     ///< Signer list (distinct per session)
    std::vector<CAMatrix::Crypto::CryptoArray> messages;   ///< Per-signer messages (raw bytes)
    std::vector<CAMatrix::Crypto::CryptoArray> signatures; ///< Per-signer signatures (serialized)
    AggregateTamperMode tamperMode = AggregateTamperMode::None; ///< Sample construction mode
};

// ==================================================================
// Identity scenario context
// ==================================================================

/**
 * @struct IdentityScenarioContext
 * @brief Holds all state created during setup() for identity verification
 * @details Contains the manager, master keys, per-user keys, and the labeled
 *          test sample set. All fields are populated in setup() and consumed
 *          in runIteration().
 */
struct IdentityScenarioContext {
    /** @brief Identity algorithm manager instance */
    std::shared_ptr<CAMatrix::Identity::Core::IdentityAlgorithmManager> manager;

    /** @brief Master public key */
    std::shared_ptr<CAMatrix::Identity::Core::AlgoPublicParams> masterPub;
    /** @brief Master private key */
    std::shared_ptr<CAMatrix::Identity::Core::AlgoPrivateParams> masterPriv;

    /**
     * @struct UserKeys
     * @brief Per-user key pair for identity verification
     */
    struct UserKeys {
        std::shared_ptr<CAMatrix::Identity::Core::AlgoUserPublicParams> pub;
        std::shared_ptr<CAMatrix::Identity::Core::AlgoUserPrivateParams> priv;
    };

    /** @brief User key map: userId → (publicKey, privateKey) */
    std::unordered_map<std::string, UserKeys> userKeys;

    /** @brief Labeled test sample set (positive + negative) */
    std::vector<IdentitySampleLabel> testSamples;

    /** @brief Online aggregate sample set (empty for offline algorithms) */
    std::vector<IdentityAggregateSample> aggregateSamples;

    /** @brief Setup stage timing measurements */
    StageTimings setupTimings;
};

// ==================================================================
// IdentityVerifyScenario — concrete class
// ==================================================================

/**
 * @class IdentityVerifyScenario
 * @brief Concrete benchmark scenario for identity verification algorithms
 * @details Measures verification accuracy rate (TP+TN)/(TP+FP+TN+FN) across
 *          a labeled test sample set. Supports configurable negative sample
 *          generation: forged signatures, tampered messages, and identity
 *          impersonation. Online algorithms additionally run the aggregate
 *          scenario: n = numUsers signers under one shared session string,
 *          aggregated via aggregateSessionSignatures and verified via
 *          aggregateVerify; tampered aggregates (byte flip / roster entry
 *          removal) must be rejected, cross-session mixing and duplicate
 *          signers are counted as rejected aggregations.
 *
 *          Usage:
 *          ```cpp
 *          auto scenario = std::make_unique<IdentityVerifyScenario>("SM9Online");
 *          scenario->setup(config);
 *          for (size_t i = 0; i < config.iterations; ++i)
 *              scenario->runIteration();
 *          auto result = scenario->getLastTimings(); // etc.
 *          scenario->teardown();
 *          ```
 */
class IdentityVerifyScenario : public BenchmarkScenario {
public:
    /**
     * @brief Construct with a specific identity algorithm type and manager
     * @param algorithmType Algorithm identifier (e.g., "SM9Noncert", "SM9Online")
     * @param manager Identity algorithm manager (with algorithms already registered)
     */
    IdentityVerifyScenario(
        const std::string& algorithmType,
        std::shared_ptr<CAMatrix::Identity::Core::IdentityAlgorithmManager> manager);

    /// @brief Returns the algorithm type string
    std::string algorithmType() const override { return algorithmType_; }

    /**
     * @brief One-time setup: create manager, generate keys, build test samples
     * @param config Benchmark configuration (numUsers, samplesPerIteration, negativeSamples)
     * @throws std::invalid_argument if algorithmType is unknown
     * @throws std::runtime_error if kind() and dynamic_cast disagree on the
     *         Online/Offline tier of the loaded algorithm
     */
    void setup(const BenchmarkConfig& config) override;

    /// @brief Identity: no pre-iteration preparation needed
    void prepare(const BenchmarkConfig& /*config*/) override {}

    /**
     * @brief Run one iteration: verify all test samples, compute TP/FP/TN/FN
     * @return true if iteration completed successfully
     */
    bool runIteration() override;

    /// @brief Records per-sample TP/FP/TN/FN outcomes from the last iteration
    void recordIteration(MetricsCollector& collector) override;

    /// @brief Returns an IdentityResult populated via MetricsCollector::fillIdentityResult()
    std::unique_ptr<BenchmarkResult> computeResult(
        const MetricsCollector& collector, const BenchmarkConfig& config) override;

    /// @brief Returns setup stage timings
    StageTimings getSetupTimings() const override;

    /// @brief Returns timings from the most recent runIteration()
    StageTimings getLastTimings() const override;

    /// @brief Returns message sizes from the most recent runIteration()
    MessageSizes getLastMessageSizes() const override;

    /**
     * @brief Release all held resources
     */
    void teardown() override;

    // ── Iteration result accessors ──

    /// @brief Accuracy rate from the most recent iteration
    double lastAccuracyRate() const { return lastAccuracyRate_; }

    /// @brief True accepts (TP) from the most recent iteration
    std::size_t lastTrueAccepts() const { return lastTA_; }
    /// @brief False accepts (FP) from the most recent iteration
    std::size_t lastFalseAccepts() const { return lastFA_; }
    /// @brief True rejects (TN) from the most recent iteration
    std::size_t lastTrueRejects() const { return lastTR_; }
    /// @brief False rejects (FN) from the most recent iteration
    std::size_t lastFalseRejects() const { return lastFR_; }

    /// @brief Aggregation rejections (cross-session mixing / duplicate signer) from the most recent iteration
    std::size_t lastRejectedAggregations() const { return lastRejectedAggregation_; }

private:
    std::string algorithmType_;         ///< Algorithm type identifier
    std::shared_ptr<CAMatrix::Identity::Core::IdentityAlgorithmManager> manager_; ///< Injected manager
    IdentityScenarioContext ctx_;        ///< Scenario state from setup()
    IdentityConfig config_;            ///< Active configuration
    std::mt19937 rng_;                  ///< Random number generator

    // ── Online (session-coordinated) tier state ──
    bool isOnline_ = false;             ///< Whether the algorithm derives from OnlineIdentitySigningAlgorithm
    std::shared_ptr<CAMatrix::Identity::Core::OnlineIdentitySigningAlgorithm>
        onlineAlgo_;                    ///< Online tier handle (nullptr for offline algorithms)
    std::size_t sessionCounter_ = 0;    ///< Internal session counter for makeSessionString (NOT a CLI parameter)

    // ── Last iteration results ──
    double lastAccuracyRate_ = 0;       ///< Accuracy rate from last iteration
    std::size_t lastTA_ = 0;           ///< True accepts from last iteration
    std::size_t lastFA_ = 0;           ///< False accepts from last iteration
    std::size_t lastTR_ = 0;           ///< True rejects from last iteration
    std::size_t lastFR_ = 0;           ///< False rejects from last iteration
    std::size_t lastRejectedAggregation_ = 0; ///< Aggregation rejections from last iteration
    StageTimings lastTimings_;          ///< Per-stage timings from last iteration
    MessageSizes lastMessageSizes_;     ///< Message sizes from last iteration

    // ── Private helpers ──

    /**
     * @brief Generate labeled test sample set (positive + negative)
     * @param config Configuration with negative sample ratios
     * @return Vector of labeled test samples
     */
    std::vector<IdentitySampleLabel> generateTestSamples(
        const IdentityConfig& config);

    /**
     * @brief Generate the online aggregate sample set (n = numUsers signers)
     * @details Auto-enabled for online algorithms with numUsers >= 2 (no extra
     *          CLI parameter). Legal and verify-path tampered aggregate sample
     *          counts are equal (doc §2.3 口径) so aggregate accuracy is
     *          unbiased; cross-session mixing and duplicate-signer samples are
     *          counted as rejected aggregations.
     * @param config Configuration (numUsers = signers per aggregate sample)
     * @return Vector of aggregate samples (empty for offline algorithms)
     */
    std::vector<IdentityAggregateSample> generateAggregateSamples(
        const IdentityConfig& config);

    /**
     * @brief Create a unique bench session string
     * @details sessionId = "bench-" + internal incrementing counter,
     *          context = "IdentityVerify". Guarantees cross-session
     *          uniqueness (a signer signs at most once per session).
     * @return Session string from onlineAlgo_->makeSessionString()
     */
    std::string makeBenchSessionString();

    /**
     * @brief Pick a random user ID from the configured user set
     * @param numUsers Total number of users
     * @return User ID string (e.g., "user-3")
     */
    std::string randomUserId(std::size_t numUsers);

    /**
     * @brief Pick a random user ID different from the given one
     * @param numUsers Total number of users
     * @param excludeId User ID to exclude
     * @return A different user ID string
     */
    std::string randomOtherUserId(std::size_t numUsers,
                                  const std::string& excludeId);

    /**
     * @brief Generate a random message string
     * @return A random hex-encoded message string
     */
    std::string randomMessage();

    /**
     * @brief Tamper a message by flipping a byte
     * @param message Original message
     * @return Tampered message with one byte changed
     */
    std::string tamperMessage(const std::string& message);
};

} // namespace CAMatrix::Audit::Benchmark

#endif // CAMATRIX_AUDIT_BENCHMARK_IDENTITY_VERIFY_SCENARIO_H
