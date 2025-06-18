#pragma once

#include <functional>
#include <future>
#include <string>
#include <tuple>
#include <vector>

#include <VbsEnclave\HostApp\Stubs.h>

#include "keycredentialmanager.vtl0.h"

std::wstring GetAlgorithm(uintptr_t ecdhAlgorithm)
{
    if (reinterpret_cast<BCRYPT_ALG_HANDLE>(ecdhAlgorithm) == BCRYPT_ECDH_P384_ALG_HANDLE)
    {
        return KeyAlgorithmNames::Ecdh384;
    }
    THROW_HR(E_INVALIDARG);
}

std::vector<std::uint8_t> veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_create_callback(_In_ const std::wstring& key_name, _In_ uintptr_t ecdhAlgorithm, uintptr_t windowId)
{
    auto algorithm = GetAlgorithm(ecdhAlgorithm);

    auto cacheConfiguration = KeyCredentialCacheConfiguration(
        KeyCredentialCacheOption::NoCache,
        300, // KeyCredentialCacheTimeout
        5); // KeyCredentialCacheUsageCount

    auto credential = winrt::Windows::Security::Credentials::RequestCreateAsync(
        key_name.c_str(),
        algorithm,
        KeyCredentialCreationOption::FailIfExists,
        cacheConfiguration,
        (winrt::Windows::UI::WindowId)windowId,
        [](const auto& challenge) mutable
        {
            auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(nullptr);
            auto attestationReport = enclaveInterface.userboundkey_get_attestation_report(challenge);  // !!! call into enclave !!!
            return attestationReport;
        }
    ).get();

    return credential.RetrieveAuthorizationContext();
}

std::vector<std::uint8_t> veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_load_callback(_In_ const std::wstring& key_name, uintptr_t windowId)
{
    auto credential = winrt::Windows::Security::Credentials::RequestOpenAsync(
        key_name.c_str(),
        (winrt::Windows::UI::WindowId)windowId,
        [] (const auto& challenge) mutable
    {
        auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(nullptr);
        auto attestationReport = enclaveInterface.userboundkey_get_attestation_report(challenge);  // !!! call into enclave !!!
        return attestationReport;
    }
    ).get();

    return credential.RetrieveAuthorizationContext();
}
