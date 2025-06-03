#pragma once

#include <string>
#include <functional>
#include <future>
#include <vector>

using blob = std::vector<uint8_t>;


// Callback invoked with the challenge. Returns the attestation report.
//using AuthenticatedSessionChallengeCallback = std::function<blob(const blob& challenge)>;

enum class KeyCredentialCacheOption
{
    NoCache,
    TimeBased,
    UsageBased,
    TimeAndUsageBased
};

struct KeyCredentialCacheConfiguration
{
    KeyCredentialCacheOption option;
    uint32_t timeoutSeconds;
    uint32_t usageCount;

    KeyCredentialCacheConfiguration(
        KeyCredentialCacheOption opt,
        uint32_t timeout,
        uint32_t usage)
        : option(opt), timeoutSeconds(timeout), usageCount(usage)
    {}
};

// Placeholder types to match usage.
namespace KeyAlgorithmNames {
    inline const std::wstring Ecdh384 = L"ECDH384";
}

enum class KeyCredentialCreationOption {
    ReplaceExisting,
    FailIfExists,
    // Add more as needed
};

// Represents the result of RequestCreateAsync.
class CreatedCredential
{
public:
    blob RetrieveSecureIdOwnerIdMatchResult() const;
    blob RetrieveCacheConfiguration() const;
    blob RetrievePublicKey() const;
};

// Asynchronous function to create a credential and perform authenticated challenge.
template <typename AuthenticatedSessionChallengeCallback>
std::future<CreatedCredential> RequestCreateAsync(
    const std::wstring& credentialName,
    const std::wstring& algorithm,
    KeyCredentialCreationOption creationOption,
    const KeyCredentialCacheConfiguration& cacheConfig,
    AuthenticatedSessionChallengeCallback&& challengeCallback);

