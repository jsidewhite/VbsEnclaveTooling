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
    else if (reinterpret_cast<BCRYPT_ALG_HANDLE>(ecdhAlgorithm) == BCRYPT_ECDH_P256_ALG_HANDLE)
    {
        return KeyAlgorithmNames::Ecdh256;
    }
    THROW_HR(E_INVALIDARG);
}

authContextBlobAndSessionKeyPtr veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_create_callback(
    const std::wstring& key_name,
    uintptr_t ecdhAlgorithm,
    const std::wstring& message,
    uintptr_t windowId)
{
    auto algorithm = GetAlgorithm(ecdhAlgorithm);

    auto cacheConfiguration = KeyCredentialCacheConfiguration(
        KeyCredentialCacheOption::NoCache,
        300, // KeyCredentialCacheTimeout
        5); // KeyCredentialCacheUsageCount

    uintptr_t sessionKeyPtr;
    auto credential = winrt::Windows::Security::Credentials::RequestCreateAsync(
        key_name.c_str(),
        algorithm,
        message,
        KeyCredentialCreationOption::FailIfExists,
        cacheConfiguration,
        (winrt::Windows::UI::WindowId)windowId,
        winrt::Windows::Security::Credentials::CallbackType::VBSEnclave,
        [&sessionKeyPtr](const auto& challenge) mutable
        {
            auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(nullptr);
            auto attestationReportAndSessionKeyPtr = enclaveInterface.userboundkey_get_attestation_report(challenge);  // !!! call into enclave !!!
            sessionKeyPtr = attestationReportAndSessionKeyPtr.sessionKey;
            return attestationReportAndSessionKeyPtr.attestationReport;
        }
    ).get();

    return authContextBlobAndSessionKeyPtr(credential.RetrieveAuthorizationContext(), sessionKeyPtr);
}

secretAndAuthorizationContextAndSessionKeyPtr veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_load_callback(
    const std::wstring& key_name,
    const std::vector<uint8_t>& ephemeralPublicKeyBytes,
    const std::wstring& message,
    uintptr_t windowId)
{
    uintptr_t sessionKeyPtr;
    auto credential = winrt::Windows::Security::Credentials::OpenAsync(
        key_name.c_str(),
        winrt::Windows::Security::Credentials::CallbackType::VBSEnclave,
        [&sessionKeyPtr] (const auto& challenge) mutable
        {
            auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(nullptr);
            auto attestationReportAndSessionKeyPtr = enclaveInterface.userboundkey_get_attestation_report(challenge);  // !!! call into enclave !!!
            sessionKeyPtr = attestationReportAndSessionKeyPtr.sessionKey;
            return attestationReportAndSessionKeyPtr.attestationReport;
        }
    ).get();

    auto authorizationContext = credential.RetrieveAuthorizationContext();
    auto secret = credential.RequestDeriveSharedSecretAsync(message, ephemeralPublicKeyBytes, (winrt::Windows::UI::WindowId)windowId).get();

    return secretAndAuthorizationContextAndSessionKeyPtr(secret, authorizationContext, sessionKeyPtr);
}
