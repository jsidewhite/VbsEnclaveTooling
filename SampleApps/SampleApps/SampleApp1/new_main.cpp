#include <iostream>
#include <fstream>
#include <string>
#include <conio.h> // For getch()
#include <filesystem> // For directory validation

#include <windows.h>
#include <stdio.h>
#include <wil/resource.h>
#include <wil/result_macros.h>
#include <span>
#include <sddl.h>
#include <limits>

#include <veil\host\enclave_api.vtl0.h>
#include <veil\host\logger.vtl0.h>

#include "sample_utils.h"

#include <VbsEnclave\HostApp\Stubs.h>

namespace fs = std::filesystem;

int EncryptData(
    void* enclave,
    const std::wstring& inputData)
{

    std::wstring helloKeyName = L"MyEncryptionKey-001";
    std::wstring pinMessage = L"Please enter your PIN to access the encryption key.";

    //
    // [Create flow]
    // 
    //  Generate secured key in enclave, then pass the encrypted key bytes to vtl0
    //

    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::VTL0_Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    HWND hCurWnd = GetForegroundWindow(); // TODO: Is this correct?

    // TODO: Do we fork between a Create flow and a Load flow here? 

    // Call into enclave
    auto securedEncryptionKeyBytes = std::vector<uint8_t> {};
    THROW_IF_FAILED(enclaveInterface.EnclaveCreateUserBoundKey(
        helloKeyName,
        pinMessage,
        hCurWnd
        securedEncryptionKeyBytes));

    // We now have our encryption key's bytes, which are sealed!
    //
    //  Meaning of sealed:
    //
    //      1. Our encryption key is sealed by the enclave (i.e. can only be unsealed
    //          by the sealing-enclave or an enclave signed with compatible signature).

    // ***Save securedEncryptionKeyBytes to disk

    //
    // [Load flow]
    // 
    //  Pass the (encrypted) key bytes and the input into enclave to encrypt, store the encrypted bytes to disk
    //

    // Call into enclave
    auto encryptedInputBytes = std::vector<uint8_t> {};
    auto tag = std::vector<uint8_t> {};

    THROW_IF_FAILED(enclaveInterface.EnclaveLoadUserBoundKeyAndEncryptData(
        helloKeyName,
        pinMessage,
        hCurWnd,
        securedEncryptionKeyBytes,
        inputData,
        encryptedInputBytes,
        tag
    ));

    // ***Save encryptedInputBytes to disk

    return 0;
}
