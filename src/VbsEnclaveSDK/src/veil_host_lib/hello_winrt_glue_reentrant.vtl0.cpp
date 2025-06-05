#pragma once

#include <functional>
#include <future>
#include <string>
#include <tuple>
#include <vector>

#include <VbsEnclave\HostApp\Stubs.h>

#include "keycredentialmanager.vtl0.h"

std::vector<std::uint8_t> veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_callback(_In_ const std::wstring& key_name)
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
        [](const auto& challenge) mutable
        {
            auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(nullptr);
            auto attestationReport = enclaveInterface.userboundkey_get_attestation_report(challenge);  // !!! call into enclave !!!
            return attestationReport;
        }
    ).get();

    auto secureIdAndOwnerIdMatch = credential.RetrieveSecureIdOwnerIdMatchResult();
    auto credentialCacheConfiguration = credential.RetrieveCacheConfiguration();
    auto credentialPublicKey = credential.RetrievePublicKey();

    std::vector<std::uint8_t> authBlob;
    authBlob.insert(authBlob.end(), secureIdAndOwnerIdMatch.begin(), secureIdAndOwnerIdMatch.end());
    authBlob.insert(authBlob.end(), credentialCacheConfiguration.begin(), credentialCacheConfiguration.end());
    authBlob.insert(authBlob.end(), credentialPublicKey.begin(), credentialPublicKey.end());

    return authBlob;
}
