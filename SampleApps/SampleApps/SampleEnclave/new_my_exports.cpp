// Copyright (c) Microsoft Corporation.
//

#include "pch.h"

#include <array>
#include <stdexcept>

#include <veil\enclave\crypto.vtl1.h>
#include <veil\enclave\logger.vtl1.h>
#include <veil\enclave\taskpool.vtl1.h>
#include <veil\enclave\vtl0_functions.vtl1.h>

#include <VbsEnclave\Enclave\Implementations.h>
#include <vector>

//
// Secured encryption key
//
HRESULT VbsEnclave::VTL1_Declarations::EnclaveCreateUserBoundKey(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ HWND windowId,
    _Out_ std::vector<std::uint8_t>& securedEncryptionKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;

    // TODO: if the key already exists, we should skip creating a new key?

    securedEncryptionKeyBytes = veil::vtl1::userboundkey::enclave_create_user_bound_key(
        helloKeyName,
        KEY_CREDENTIAL_CACHE_CONFIG {}, // TODO: is this needed? Because we are creating it in userboundkey_establish_session_for_create_callback
        pinMessage,
        windowId,
        ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_EXACT_CODE);

    return S_OK;
}

HRESULT VbsEnclave::VTL1_Declarations::EnclaveLoadUserBoundKeyAndEncryptData(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ HWND windowId,
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::wstring& dataToEncrypt,
    _Out_  std::vector<std::uint8_t>& encryptedInputBytes,
    _Out_  std::vector<std::uint8_t>& tag)
{
    using namespace veil::vtl1::vtl0_functions;

    // if (!IsUserBoundKeyLoaded()) TODO?
    auto encryptionKey = veil::vtl1::userboundkey::enclave_load_user_bound_key(
        helloKeyName,
        KEY_CREDENTIAL_CACHE_CONFIG {}, // TODO: is this needed?
        pinMessage,
        windowId,
        securedEncryptionKeyBytes);

    //
    // Now let's encrypt the input data with our encryption key
    //

    // Encrypting the user input data
    auto const inputData = dataToEncrypt.c_str();

    // Let's encrypt the input text
    auto [encryptedText, encryptionTag] = veil::vtl1::crypto::encrypt(encryptionKey.get(), veil::vtl1::as_data_span(inputData), veil::vtl1::crypto::zero_nonce);

    // Return the encrypted input to vtl0 host caller...
    encryptedInputBytes.assign(encryptedText.begin(), encryptedText.end());
    tag.assign(encryptionTag.begin(), encryptionTag.end());

    return true;
}
