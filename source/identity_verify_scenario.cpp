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
 * @file identity_verify_scenario.cpp
 * @brief Identity verification benchmark scenario implementation
 * @details Implements the setup/runIteration/teardown lifecycle for identity
 *          verification benchmarking. Setup creates master and user keys;
 *          each iteration generates fresh labeled samples, signatures, and
 *          Online sessions, then measures verification accuracy. Both Online
 *          and Offline algorithms aggregate through IdentitySigningAlgorithm
 *          using an AggregateRequest.
 * @author Dylan Liu
 * @version 2.1.0
 * @date 2026-08-25
 */

#include <ChordAuditMatrixBench/identity_verify_scenario.h>

// ── Framework ──
#include <ChordAuditMatrixBench/benchmark_types.h>

// ── Identity manager ──
#include "ChordAuditMatrixLib/interfaces/identity/identity_algorithm_manager.h"
#include "ChordAuditMatrixLib/interfaces/identity/identity_algorithm_params.h"
#include "ChordAuditMatrixLib/interfaces/identity/identity_request.h"
#include "ChordAuditMatrixLib/interfaces/identity/online_identity_signing_algorithm.h"

// ── AuditDataMap for algorithm input ──
#include "ChordAuditMatrixLib/interfaces/audit/messages/audit_data_map.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <random>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace CAMatrix::Audit::Benchmark {

namespace {

/**
 * @brief Measure execution time of a callable in milliseconds
 * @tparam F Callable type
 * @param f Callable to measure
 * @return Execution time in milliseconds
 */
template <typename F>
double measureMs(F&& f)
{
    auto t0 = std::chrono::steady_clock::now();
    std::forward<F>(f)();
    auto t1 = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

void addTiming(TimingMetric& metric, double totalMs, std::size_t callCount = 1)
{
    metric.totalMs += totalMs;
    metric.callCount += callCount;
    metric.averageMs = (metric.callCount > 0)
        ? metric.totalMs / static_cast<double>(metric.callCount) : 0.0;
}
void addMessage(MessageMetric& metric, std::size_t bytes)
{
    metric.totalBytes += bytes;
    ++metric.messageCount;
    metric.averageBytes = static_cast<double>(metric.totalBytes)
        / static_cast<double>(metric.messageCount);
}

/**
 * @brief Measure one attempted operation and include failures in its count
 */
template <typename F>
auto measureCall(TimingMetric* metric, F&& f) -> std::invoke_result_t<F>
{
    if (!metric) {
        return std::forward<F>(f)();
    }

    auto t0 = std::chrono::steady_clock::now();
    try {
        auto result = std::forward<F>(f)();
        auto t1 = std::chrono::steady_clock::now();
        addTiming(*metric,
                  std::chrono::duration<double, std::milli>(t1 - t0).count());
        return result;
    } catch (...) {
        auto t1 = std::chrono::steady_clock::now();
        addTiming(*metric,
                  std::chrono::duration<double, std::milli>(t1 - t0).count());
        throw;
    }
}

/**
 * @brief Sign a message with a supplied private key
 */
CAMatrix::Crypto::CryptoArray signWithPrivateKey(
    const std::string& userId,
    const CAMatrix::Crypto::CryptoArray& message,
    const IdentityScenarioContext& ctx,
    const std::string& algorithmType,
    const std::shared_ptr<CAMatrix::Identity::Core::AlgoUserPrivateParams>& userPriv,
    const std::string& sessionString,
    TimingMetric* timing,
    MessageMetric* messageMetric)
{
    CAMatrix::Audit::Messages::AuditDataMap signInput;
    signInput.emplace("message", message);
    signInput.emplace("userId", userId);
    signInput.emplace("masterPub", ctx.masterPub);
    signInput.emplace("userPriv", userPriv);
    if (!sessionString.empty()) {
        signInput.emplace("sessionString", sessionString);
    }

    auto algo = ctx.manager->getIdentityAlgorithm(algorithmType);
    auto signature = measureCall(timing, [&]() {
        auto variant = algo->createRequest(
            CAMatrix::Identity::Core::IdentityOperation::Sign, signInput);
        auto req = std::get<std::shared_ptr<
            CAMatrix::Identity::Core::SignRequest>>(*variant);
        return algo->sign(*req);
    });
    if (messageMetric) {
        addMessage(*messageMetric, signature.size());
    }
    return signature;
}

/**
 * @brief Sign a message with a user's private key → σᵢ (raw bytes)
 */
CAMatrix::Crypto::CryptoArray signForUser(
    const std::string& userId,
    const CAMatrix::Crypto::CryptoArray& message,
    const IdentityScenarioContext& ctx,
    const std::string& algorithmType,
    const std::string& sessionString = {},
    TimingMetric* timing = nullptr,
    MessageMetric* messageMetric = nullptr)
{
    auto it = ctx.userKeys.find(userId);
    if (it == ctx.userKeys.end()) {
        throw std::invalid_argument("signForUser: unknown user " + userId);
    }
    return signWithPrivateKey(
        userId, message, ctx, algorithmType, it->second.priv,
        sessionString, timing, messageMetric);
}

/**
 * @brief Fill a sample with numUsers legitimate signatures over one message
 */
void fillLegitSigners(IdentitySampleLabel& sample,
                      const CAMatrix::Crypto::CryptoArray& message,
                      const IdentityScenarioContext& ctx,
                      const std::string& algorithmType,
                      std::size_t numUsers,
                      const std::string& sessionString = {},
                      TimingMetric* timing = nullptr,
                      MessageMetric* messageMetric = nullptr)
{
    for (std::size_t j = 0; j < numUsers; ++j) {
        auto userId = "user-" + std::to_string(j);
        auto it = ctx.userKeys.find(userId);
        if (it == ctx.userKeys.end()) {
            continue;
        }

        sample.signatures.push_back(
            signForUser(userId, message, ctx, algorithmType, sessionString,
                        timing, messageMetric));
        sample.userIds.push_back(userId);
        sample.userPubKeys.push_back(it->second.pub);
    }
}

} // anonymous namespace

// ==================================================================
// Construction
// ==================================================================

IdentityVerifyScenario::IdentityVerifyScenario(
    const std::string& algorithmType,
    std::shared_ptr<CAMatrix::Identity::Core::IdentityAlgorithmManager> manager)
    : algorithmType_(algorithmType)
    , manager_(std::move(manager))
    , rng_(std::random_device{}())
{
    if (!manager_) {
        throw std::invalid_argument("IdentityVerifyScenario: manager must not be null");
    }
}

// ==================================================================
// setup()
// ==================================================================

void IdentityVerifyScenario::setup(const BenchmarkConfig& config)
{
    const auto& cfg = dynamic_cast<const IdentityConfig&>(config);
    config_ = cfg;
    ctx_ = IdentityScenarioContext{};
    ctx_.setupTimings = StageTimings{};
    ctx_.setupMessageSizes = MessageSizes{};

    // Seed the RNG if pseudo-random mode is requested.
    if (cfg.usePseudoRandom) {
        rng_.seed(cfg.seed);
    }

    // ── Step 1: Use injected manager ──
    ctx_.manager = manager_;

    // ── Step 2: Kind dispatch — online (session-coordinated) vs offline ──
    {
        auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
        auto onlineAlgo = std::dynamic_pointer_cast<
            CAMatrix::Identity::Core::OnlineIdentitySigningAlgorithm>(algo);
        isOnline_ = (onlineAlgo != nullptr);
        onlineAlgo_ = std::move(onlineAlgo);

        const bool kindOnline =
            (algo->kind() == CAMatrix::Identity::Core::IdentityAlgorithmKind::Online);
        if (isOnline_ != kindOnline) {
            spdlog::error("IdentityVerifyScenario: kind()/dynamic_cast mismatch for algorithm '{}' "
                          "(derived from Online tier: {}, kind() == Online: {})",
                          algorithmType_, isOnline_, kindOnline);
            throw std::runtime_error(
                "IdentityVerifyScenario: kind()/dynamic_cast mismatch — algorithm '" +
                algorithmType_ + "' violates the Online/Offline tier contract");
        }
    }

    // ── Step 3: Generate the master key pair ──
    auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
    auto masterKeys = measureCall(&ctx_.setupTimings.initAlgorithm, [&]() {
        return algo->generateMasterKey();
    });
    ctx_.masterPub = masterKeys.first;
    ctx_.masterPriv = masterKeys.second;

    // ── Step 4: Derive per-user key pairs ──
    for (std::size_t i = 0; i < cfg.numUsers; ++i) {
        auto userId = "user-" + std::to_string(i);
        auto userKeys = measureCall(&ctx_.setupTimings.generateKeys, [&]() {
            return algo->deriveUserKey(
                *ctx_.masterPub, *ctx_.masterPriv, userId);
        });
        auto& keys = ctx_.userKeys[userId];
        keys.pub = userKeys.first;
        keys.priv = userKeys.second;

        if (keys.priv) {
            auto& keyMetric = ctx_.setupMessageSizes.keyGeneration;
            keyMetric.totalBytes += keys.priv->serialize().size();
            ++keyMetric.messageCount;
            keyMetric.averageBytes =
                static_cast<double>(keyMetric.totalBytes)
                / static_cast<double>(keyMetric.messageCount);
        }
    }
    // Derive the external attacker key once during setup. Forgery samples
    // reuse it so per-iteration work contains signing, not key generation.
    if (cfg.numUsers >= 2 && cfg.negativeSamples.forgeryRatio > 0.0) {
        try {
            auto forgerKeys = measureCall(&ctx_.setupTimings.generateKeys, [&]() {
                return algo->deriveUserKey(
                    *ctx_.masterPub, *ctx_.masterPriv, "forger-external");
            });
            ctx_.forgerPriv = forgerKeys.second;
            if (ctx_.forgerPriv) {
                addMessage(ctx_.setupMessageSizes.keyGeneration,
                           ctx_.forgerPriv->serialize().size());
            }
        } catch (...) {
            ctx_.forgerPriv.reset();
        }
    }

}

// ==================================================================
// runIteration()
// ==================================================================

bool IdentityVerifyScenario::runIteration()
{
    using AuditDataMap = CAMatrix::Audit::Messages::AuditDataMap;

    lastTA_ = lastFA_ = lastTR_ = lastFR_ = 0;
    lastTimings_ = StageTimings{};
    lastMessageSizes_ = MessageSizes{};

    // Samples, negative variants, signatures, and sessions are fresh per iteration.
    ctx_.testSamples = generateTestSamples(config_);

    for (const auto& sample : ctx_.testSamples) {
        CAMatrix::Crypto::CryptoArray msgBytes(sample.message.begin(), sample.message.end());

        // ── 1. Aggregate individual signatures → Σ ──
        CAMatrix::Crypto::CryptoArray aggSig;
        bool accepted = false;
        try {
            aggSig = measureCall(&lastTimings_.aggregate, [&]() {
                AuditDataMap aggInput;
                aggInput.emplace(std::string(
                    CAMatrix::Identity::Core::IdentityVerifyContract::kMessage), msgBytes);
                aggInput.emplace(std::string(
                    CAMatrix::Identity::Core::IdentityVerifyContract::kSignatures),
                    sample.signatures);
                aggInput.emplace(std::string(
                    CAMatrix::Identity::Core::IdentityVerifyContract::kUserIds),
                    sample.userIds);
                aggInput.emplace(std::string(
                    CAMatrix::Identity::Core::IdentityVerifyContract::kUserPubKeys),
                    sample.userPubKeys);
                aggInput.emplace(std::string(
                    CAMatrix::Identity::Core::IdentityVerifyContract::kSessionString),
                    sample.sessionString);
                aggInput.emplace(std::string(
                    CAMatrix::Identity::Core::IdentityVerifyContract::kMasterPub),
                    ctx_.masterPub);
                auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
                auto aggVariant = algo->createRequest(
                    CAMatrix::Identity::Core::IdentityOperation::Aggregate, aggInput);
                auto aggReq = std::get<std::shared_ptr<
                    CAMatrix::Identity::Core::AggregateRequest>>(*aggVariant);
                return algo->aggregate(*aggReq);
            });
        } catch (...) {
            if (!sample.shouldAccept) ++lastTR_;
            else ++lastFR_;
            continue;
        }
        if (aggSig.empty()) {
            if (!sample.shouldAccept) ++lastTR_;
            else ++lastFR_;
            continue;
        }
        addMessage(lastMessageSizes_.verification, aggSig.size());

        // ── 2. Aggregate-verify Σ against all signers ──
        AuditDataMap verifyInput;
        verifyInput.emplace("aggregateSignature", aggSig);
        verifyInput.emplace("message", msgBytes);
        verifyInput.emplace("masterPub", ctx_.masterPub);
        verifyInput.emplace("userIds", sample.userIds);
        verifyInput.emplace("userPubKeys", sample.userPubKeys);
        verifyInput.emplace(std::string(
            CAMatrix::Identity::Core::IdentityVerifyContract::kSessionString),
            sample.sessionString);

        accepted = measureCall(&lastTimings_.aggregateVerify, [&]() {
            auto algo = ctx_.manager->getIdentityAlgorithm(algorithmType_);
            auto variant = algo->createRequest(
                CAMatrix::Identity::Core::IdentityOperation::Verify, verifyInput);
            auto req = std::get<std::shared_ptr<
                CAMatrix::Identity::Core::AggregateVerifyRequest>>(*variant);
            return algo->aggregateVerify(*req);
        });

        // ── Count TP/FP/TN/FN ──
        if (sample.shouldAccept && accepted) {
            ++lastTA_;
        } else if (!sample.shouldAccept && accepted) {
            ++lastFA_;
        } else if (!sample.shouldAccept && !accepted) {
            ++lastTR_;
        } else {
            ++lastFR_;
        }
    }

    std::size_t total = lastTA_ + lastFA_ + lastTR_ + lastFR_;
    lastAccuracyRate_ = (total > 0)
        ? static_cast<double>(lastTA_ + lastTR_) / static_cast<double>(total)
        : 0.0;

    return true;
}

// ==================================================================
// Accessors
// ==================================================================

StageTimings IdentityVerifyScenario::getSetupTimings() const
{
    return ctx_.setupTimings;
}
MessageSizes IdentityVerifyScenario::getSetupMessageSizes() const
{
    return ctx_.setupMessageSizes;
}


StageTimings IdentityVerifyScenario::getLastTimings() const
{
    return lastTimings_;
}

MessageSizes IdentityVerifyScenario::getLastMessageSizes() const
{
    return lastMessageSizes_;
}

// ==================================================================
// teardown()
// ==================================================================

void IdentityVerifyScenario::teardown()
{
    ctx_ = IdentityScenarioContext{};
    lastAccuracyRate_ = 0;
    lastTA_ = lastFA_ = lastTR_ = lastFR_ = 0;
    lastTimings_ = StageTimings{};
    lastMessageSizes_ = MessageSizes{};
}

// ==================================================================
// recordIteration() — record per-sample TP/FP/TN/FN from last iteration
// ==================================================================

void IdentityVerifyScenario::recordIteration(MetricsCollector& collector)
{
    // TP: accepted && shouldAccept
    for (std::size_t tp = 0; tp < lastTA_; ++tp)
        collector.recordIdentityOutcome(true, true);
    // FP: accepted && !shouldAccept
    for (std::size_t fp = 0; fp < lastFA_; ++fp)
        collector.recordIdentityOutcome(true, false);
    // TN: !accepted && !shouldAccept
    for (std::size_t tn = 0; tn < lastTR_; ++tn)
        collector.recordIdentityOutcome(false, false);
    // FN: !accepted && shouldAccept
    for (std::size_t fn = 0; fn < lastFR_; ++fn)
        collector.recordIdentityOutcome(false, true);
}

// ==================================================================
// computeResult() — returns IdentityResult
// ==================================================================

std::unique_ptr<BenchmarkResult> IdentityVerifyScenario::computeResult(
    const MetricsCollector& collector, const BenchmarkConfig& config)
{
    const auto& cfg = dynamic_cast<const IdentityConfig&>(config);
    auto result = std::make_unique<IdentityResult>();
    collector.fillIdentityResult(*result, cfg);
    result->algorithmKind = isOnline_ ? "Online" : "Offline";
    return result;
}

// ==================================================================
// generateTestSamples()
// ==================================================================

std::vector<IdentitySampleLabel>
IdentityVerifyScenario::generateTestSamples(const IdentityConfig& config)
{

    std::vector<IdentitySampleLabel> samples;
    auto& neg = config.negativeSamples;
    double positiveRatio =
        1.0 - neg.forgeryRatio - neg.tamperedRatio - neg.impersonationRatio;
    std::size_t totalSamples = config.samplesPerIteration;

    // ── 1. Positive samples: numUsers users sign the same message → aggregate ──
    std::size_t posCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * positiveRatio);
    for (std::size_t i = 0; i < posCount; ++i) {
        auto message = randomMessage();
        CAMatrix::Crypto::CryptoArray msgBytes(message.begin(), message.end());

        IdentitySampleLabel sample;
        sample.message = message;
        sample.shouldAccept = true;
        sample.sessionString = isOnline_ ? makeBenchSessionString() : "";

        fillLegitSigners(sample, msgBytes, ctx_, algorithmType_, config.numUsers,
                         sample.sessionString, &lastTimings_.sign,
                         &lastMessageSizes_.signing);
        if (sample.signatures.size() == config.numUsers) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 2. Forgery samples: aggregate with one forged signature → reject ──
    std::size_t forgeryCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * neg.forgeryRatio);

    // The external attacker key is derived once during setup. If setup could
    // not derive it, omit forgery samples while retaining other samples.
    if (!ctx_.forgerPriv) {
        forgeryCount = 0;
    }

    for (std::size_t i = 0; i < forgeryCount; ++i) {
        if (config.numUsers < 2) {
            continue;
        }

        auto message = randomMessage();
        CAMatrix::Crypto::CryptoArray msgBytes(message.begin(), message.end());

        IdentitySampleLabel sample;
        sample.message = message;
        sample.shouldAccept = false;
        sample.sessionString = isOnline_ ? makeBenchSessionString() : "";

        // Legitimate part: user-0 .. user-(N-2) sign the same message
        for (std::size_t j = 0; j < config.numUsers - 1; ++j) {
            auto userId = "user-" + std::to_string(j);
            auto it = ctx_.userKeys.find(userId);
            if (it == ctx_.userKeys.end()) {
                continue;
            }

            sample.signatures.push_back(signForUser(
                userId, msgBytes, ctx_, algorithmType_, sample.sessionString,
                &lastTimings_.sign, &lastMessageSizes_.signing));
            sample.userIds.push_back(userId);
            sample.userPubKeys.push_back(it->second.pub);
        }

        // Forgery part: forge a signature with an UNREGISTERED key pair
        // (external attacker — not in the user pool), claiming to be
        // user-(N-1) → aggregate verification must reject.
        auto victimId = "user-" + std::to_string(config.numUsers - 1);
        auto victimKeyIt = ctx_.userKeys.find(victimId);
        if (victimKeyIt == ctx_.userKeys.end()) {
            continue;
        }

        try {
            sample.signatures.push_back(signWithPrivateKey(
                "forger-external", msgBytes, ctx_, algorithmType_, ctx_.forgerPriv,
                sample.sessionString, &lastTimings_.sign,
                &lastMessageSizes_.signing));
            sample.userIds.push_back(victimId);   // claims to be user-(N-1)
            sample.userPubKeys.push_back(victimKeyIt->second.pub);
        } catch (...) {
            continue;
        }

        if (sample.signatures.size() == config.numUsers) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 3. Tampered message samples: signatures over the original message,
    //    verification uses the tampered message → aggregate must reject ──
    std::size_t tamperedCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * neg.tamperedRatio);
    for (std::size_t i = 0; i < tamperedCount; ++i) {
        auto originalMsg = randomMessage();
        auto tamperedMsg = tamperMessage(originalMsg);
        CAMatrix::Crypto::CryptoArray originalBytes(originalMsg.begin(), originalMsg.end());

        IdentitySampleLabel sample;
        sample.message = tamperedMsg;   // verification uses the tampered message
        sample.shouldAccept = false;
        sample.sessionString = isOnline_ ? makeBenchSessionString() : "";

        fillLegitSigners(sample, originalBytes, ctx_, algorithmType_, config.numUsers,
                         sample.sessionString, &lastTimings_.sign,
                         &lastMessageSizes_.signing);
        if (sample.signatures.size() == config.numUsers) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 4. Impersonation samples: one signer claims another identity → reject ──
    std::size_t impCount = static_cast<std::size_t>(
        static_cast<double>(totalSamples) * neg.impersonationRatio);
    for (std::size_t i = 0; i < impCount; ++i) {
        if (config.numUsers < 2) {
            continue;
        }

        auto message = randomMessage();
        CAMatrix::Crypto::CryptoArray msgBytes(message.begin(), message.end());

        IdentitySampleLabel sample;
        sample.message = message;
        sample.shouldAccept = false;
        sample.sessionString = isOnline_ ? makeBenchSessionString() : "";

        // Legitimate part: user-0 .. user-(N-2)
        for (std::size_t j = 0; j < config.numUsers - 1; ++j) {
            auto userId = "user-" + std::to_string(j);
            auto it = ctx_.userKeys.find(userId);
            if (it == ctx_.userKeys.end()) {
                continue;
            }

            sample.signatures.push_back(signForUser(
                userId, msgBytes, ctx_, algorithmType_, sample.sessionString,
                &lastTimings_.sign, &lastMessageSizes_.signing));
            sample.userIds.push_back(userId);
            sample.userPubKeys.push_back(it->second.pub);
        }

        // Impersonation part: signed with user-0's key, claims to be user-(N-1)
        auto victimId = "user-" + std::to_string(config.numUsers - 1);
        auto victimKeyIt = ctx_.userKeys.find(victimId);
        auto impersonatorKeyIt = ctx_.userKeys.find("user-0");
        if (victimKeyIt == ctx_.userKeys.end() || impersonatorKeyIt == ctx_.userKeys.end()) {
            continue;
        }

        try {
            sample.signatures.push_back(signWithPrivateKey(
                "user-0", msgBytes, ctx_, algorithmType_, impersonatorKeyIt->second.priv,
                sample.sessionString, &lastTimings_.sign,
                &lastMessageSizes_.signing));
            sample.userIds.push_back(victimId);   // claims to be user-(N-1)
            sample.userPubKeys.push_back(victimKeyIt->second.pub);
        } catch (...) {
            continue;
        }

        if (sample.signatures.size() == config.numUsers) {
            samples.push_back(std::move(sample));
        }
    }

    // ── 5. Shuffle samples to avoid ordering bias ──
    std::shuffle(samples.begin(), samples.end(), rng_);

    return samples;
}

std::string IdentityVerifyScenario::makeBenchSessionString()
{
    static constexpr char hexChars[] = "0123456789abcdef";
    std::uniform_int_distribution<int> hexDist(0, 15);
    std::uniform_int_distribution<int> variantDist(8, 11);

    std::string sessionId(36, '0');
    for (std::size_t i = 0; i < sessionId.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            sessionId[i] = '-';
        } else {
            sessionId[i] = hexChars[hexDist(rng_)];
        }
    }
    sessionId[14] = '4';
    sessionId[19] = hexChars[variantDist(rng_)];

    return onlineAlgo_->makeSessionString(sessionId, "IdentityVerify");
}

// ==================================================================
// Private helpers
// ==================================================================

std::string IdentityVerifyScenario::randomMessage()
{
    // Generate a random 32-byte hex string as the message.
    static constexpr char hexChars[] = "0123456789abcdef";
    std::uniform_int_distribution<int> dist(0, 15);
    std::string msg;
    msg.reserve(64);
    for (int i = 0; i < 64; ++i) {
        msg.push_back(hexChars[dist(rng_)]);
    }
    return msg;
}

std::string IdentityVerifyScenario::tamperMessage(const std::string& message)
{
    if (message.empty()) {
        return message;
    }
    std::string tampered = message;
    // Flip the last byte's lowest bit
    tampered.back() ^= 0x01;
    return tampered;
}

} // namespace CAMatrix::Audit::Benchmark
