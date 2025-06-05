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


namespace veil::vtl0::implementation::callins
{
    ChallengeAndContext GetChallengeCallback()
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
            [p = std::move(p), f = std::move(f)](const auto& challenge) mutable
            {
                p->set_value(challenge);

                // VBS enclave application gets sealed attestation report with challenge
                auto attestationReport = f.get();
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

        auto challenge = futureChallenge.get();

        auto futureSecurityPropertiesPtr = std::make_unique<std::future<EncryptedSecurityProperties>>(std::move(futureSecurityProperties));

        // Return to enclave
        return ChallengeAndContext 
        {
            std::move(challenge),
            (uintptr_t)promiseAttestationReport.release(),
            (uintptr_t)futureSecurityPropertiesPtr.release()
        };
    }

    EncryptedSecurityProperties CreateRecallKeyCallback(blob sealedAttestationReport, uintptr_t promiseAttestationReportPtr, uintptr_t futureSecurityPropertiesPtr) noexcept
    {
        auto promiseAttestationReport = std::unique_ptr<std::promise<blob>>((std::promise<blob>*)promiseAttestationReportPtr);
        auto futureSecurityProperties = std::unique_ptr<std::future<EncryptedSecurityProperties>>((std::future<EncryptedSecurityProperties>*)futureSecurityPropertiesPtr);

        // Resume the std::async thread to give the AttestationReport to NGC
        promiseAttestationReport->set_value(sealedAttestationReport);

        // Wait for NGC to return and give us the security properties
        auto securityProperties = futureSecurityProperties->get();
        return securityProperties;
    }
}
