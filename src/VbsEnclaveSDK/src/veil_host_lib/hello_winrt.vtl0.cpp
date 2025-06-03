#pragma once

#include <functional>
#include <future>
#include <string>
#include <tuple>
#include <vector>

#include "keycredentialmanager.vtl0.h"


struct EncryptedSecurityProperties
{
    blob secureIdMatchesOwnerId;
    blob encryptedCacheConfiguration;
    blob publicKey;
};

struct ChallengeAndContext
{
    blob challenge;
    uintptr_t promiseAttestationReport; //std::promise<blob>;
    uintptr_t futureSecurityProperties; //std::future<EncryptedSecurityProperties>;
};

ChallengeAndContext GetChallengeCallback()
{
    std::promise<blob> promiseChallenge;
    std::promise<blob> promiseAttestationReport;

    auto futureChallenge = promiseChallenge.get_future();
    auto futureAttestationReport = promiseAttestationReport.get_future();

    auto spPromise = std::make_shared<std::promise<blob>>(std::move(promiseChallenge));
    auto spFuture = std::make_shared<std::future<blob>>(std::move(futureAttestationReport));

    auto futureSecurityProperties = std::async(std::launch::async, [p = spPromise, f = spFuture] () mutable
    {
        auto cacheConfiguration = KeyCredentialCacheConfiguration(
            KeyCredentialCacheOption::NoCache,
            300, // KeyCredentialCacheTimeout
            5); // KeyCredentialCacheUsageCount

        auto credential = RequestCreateAsync(
            L"myCredential",
            KeyAlgorithmNames::Ecdh384,
            KeyCredentialCreationOption::FailIfExists,
            cacheConfiguration,
            [p, f](const auto& challenge) mutable
            {
                p->set_value(challenge);
                auto attestationReport = f.get(); // PAUSE - VBS enclave application gets sealed attestation report with challenge
                return attestationReport;
            }
        ).get();

        auto secureIdAndOwnerIdMatch = credential.RetrieveSecureIdOwnerIdMatchResult();
        auto credentialCacheConfiguration = credential.RetrieveCacheConfiguration();
        auto credentialPublicKey = credential.RetrievePublicKey();

        // Let VBS enclave application verifies that the IDs and credential cache config are as expected
        return EncryptedSecurityProperties {
            secureIdAndOwnerIdMatch,
            credentialCacheConfiguration,
            credentialPublicKey
        };
    });

    auto challenge = futureChallenge.get();

    auto challengeAndContext = ChallengeAndContext
    {
        std::move(challenge),
        0,
        0
        //(uintptr_t)promiseAttestationReport.get(),
        //(uintptr_t)futureSecurityProperties.get()
    };
    return challengeAndContext;
}

EncryptedSecurityProperties CreateRecallKeyCallback(blob sealedAttestationReport, std::promise<blob> promiseAttestationReport, std::future<EncryptedSecurityProperties> futureSecurityProperties) noexcept
{
    promiseAttestationReport.set_value(sealedAttestationReport);
    auto securityProperties = futureSecurityProperties.get();
    return securityProperties;
}
