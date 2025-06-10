#pragma once

#ifndef VENGCDLL_H
#define VENGCDLL_H

//
// New OS dll (in VTL1) exports
//

// Attestation report generation API for user bound keys.
// Generates a session key, passes session key and provided challenge to EnclaveGetAttestationReport,
// encrypts the attestation report with EnclaveEncryptDataForTrustlet, returns the encrypted report. 
HRESULT GetAttestationReportForUserBoundKey(
    _In_ uint8_t* challenge,
    _In_ size_t challengeSize,
    _Out_ uint8_t** report,
    _Out_ size_t* reportSize
);

// Auth Context APIs
typedef void* USER_BOUND_KEY_AUTH_CONTEXT_HANDLE;

BOOL CloseUserBoundKeyAuthContextHandle(
    USER_BOUND_KEY_AUTH_CONTEXT_HANDLE handle);

struct CACHE_CONFIG {
    uint32_t cacheType;
    uint32_t cacheTimeout;
    uint32_t cacheCallCount;
};

enum UserBoundKeyAuthContextProperties {
    KeyName = 0, // The name of the user bound key, encoded as a UTF-8 string.
    KeyEncryptionKey = 1, // The KEK used to encrypt the user bound key, encoded as a byte array.
    CacheConfig = 2, // The cache configuration for the user bound key, encoded as a CACHE_CONFIG structure.
    SecureIdIsOwnerId = 3, // boolean, indicating whether the SecureId of the NGC key matches the OwnerId of the enclave.
};

HRESULT GetUserBoundKeyAuthContextProperty(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_ UserBoundKeyAuthContextProperties property,
    _Out_ void** value,
    _Out_ size_t* valueSize
);

// Called as part of the flow when creating a new user bound key.
// Decrypts the auth context blob provided by NGC, verifies that the keyname matches the one in the auth context blob,
// Performs key establishment using the enclave key handle provided, along with the
// corresponding key from the NGC side (present in the auth context blob).
// Computes the key encryption key (KEK) for the user bound key.
HRESULT GetAuthContextForUserBoundKeyCreation(
    _In_ PCWSTR keyName,
    _In_ BCRYPT_KEY_HANDLE enclaveKey, // The enclave key handle used to to perform key establishment.
    _In_ uint8_t* authContextBlob, // auth context generated as part of RequestCreateAsync
    _In_ size_t authContextBlobSize,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* authContextHandle
);

// Called as part of the flow when loading an existing user bound key.
// Decrypts the auth context blob provided by NGC, verifies that the keyname matches the one in the auth context blob.
HRESULT GetAuthContextForUserBoundKeyLoading(
    _In_ PCWSTR keyName,
    _In_ uint8_t* authContextBlob, // auth context generated as part of RequestCreateAsync 
    _In_ size_t authContextBlobSize,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* authContextHandle
);

#endif // VENGCDLL_H
