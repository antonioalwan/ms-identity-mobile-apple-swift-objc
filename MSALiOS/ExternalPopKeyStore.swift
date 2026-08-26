//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//

import Foundation
import MSAL
import Security

enum ExternalPopKeyStore {
    private static let keyTag = "com.microsoft.identitysample.MSALiOS.atpop.rsa"
        .data(using: .utf8)!

    static func loadOrCreate() throws -> MSALExternalKeyPair {
        let privateKey: SecKey

        if let storedKey = try loadPrivateKey() {
            privateKey = storedKey
        } else {
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits as String: 2048,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: keyTag
                ]
            ]

            var keyCreationError: Unmanaged<CFError>?
            guard let createdKey = SecKeyCreateRandomKey(
                attributes as CFDictionary,
                &keyCreationError
            ) else {
                if let error = keyCreationError?.takeRetainedValue() {
                    throw error
                }

                throw NSError(
                    domain: NSOSStatusErrorDomain,
                    code: Int(errSecParam),
                    userInfo: [NSLocalizedDescriptionKey: "Unable to create the RSA key pair."]
                )
            }

            privateKey = createdKey
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw NSError(
                domain: NSOSStatusErrorDomain,
                code: Int(errSecDecode),
                userInfo: [NSLocalizedDescriptionKey: "Unable to derive the public key."]
            )
        }

        return try MSALExternalKeyPair(privateKey: privateKey, publicKey: publicKey)
    }

    private static func loadPrivateKey() throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: keyTag,
            kSecReturnRef as String: true
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess, let result = result else {
            throw NSError(
                domain: NSOSStatusErrorDomain,
                code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "Unable to load the stored RSA key pair."]
            )
        }

        return (result as! SecKey)
    }
}
