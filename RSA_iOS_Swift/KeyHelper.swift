//
//  KeyHelper.swift
//  RSA_iOS_Swift
//
//  Created by Anuradh Caldera on 12/2/19.
//  Copyright © 2019 https://www.linkedin.com/in/anuradhcaldera/. All rights reserved.
//

import Foundation
import CommonCrypto

struct KeyHelper {
    private var osstatus: OSStatus?
    private var publickey: SecKey?
    private var privatekey: SecKey?
}

//MARK: - Generating RSA Key Pair
extension KeyHelper {
    
    mutating func generateRSAKeyPair(length: Int, completion: @escaping(String?, String?) -> ()) {
        
        let publicKeyAttributes: [NSObject: NSObject] = [
            kSecAttrIsPermanent: true as NSObject,
            kSecAttrApplicationTag: "com.anuradh.rsaiosswift.publickkey" as NSObject,
            kSecClass: kSecClassKey,
            kSecReturnData: kCFBooleanTrue
        ]
        
        let privateKeyAttributes: [NSObject: NSObject] = [
            kSecAttrIsPermanent: true as NSObject,
            kSecAttrApplicationTag: "com.anuradh.rsaiosswift.privatekey" as NSObject,
            kSecClass: kSecClassKey,
            kSecReturnData: kCFBooleanTrue
        ]
        
        let keypairAttributes: [NSObject: NSObject] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: length as NSObject,
            kSecPublicKeyAttrs: publicKeyAttributes as NSObject,
            kSecPrivateKeyAttrs: privateKeyAttributes as NSObject
        ]
        
        let status: OSStatus = SecKeyGeneratePair(keypairAttributes as CFDictionary, &publickey, &privatekey)
        
        if status == noErr && publickey != nil && privatekey != nil {
            
            var _publickey: AnyObject?
            var _privatekey: AnyObject?
            
            let statusPublic: OSStatus = SecItemCopyMatching(publicKeyAttributes as CFDictionary, &_publickey)
            let statusPrivate: OSStatus = SecItemCopyMatching(privateKeyAttributes as CFDictionary, &_privatekey)
            
            if statusPublic == noErr && statusPrivate == noErr {
                if let _publickeydata = _publickey as? Data, let _privatekeydata = _privatekey as? Data {
                    
                    completion(_publickeydata.base64EncodedString(), _privatekeydata.base64EncodedString())
                    return
                }
            }
            completion(nil, nil)
            return
        }
        completion(nil, nil)
        return
    }
}

//MARK: - Sign With Private Key
extension KeyHelper {
    func signTextWithPrivateKey(key privatekeystring: String,withtext text: String, completion: @escaping(String?) -> ()) {
        
        if let _privatekeyData: Data = Data(base64Encoded: privatekeystring) {
            
            let keyDictionary: [NSObject: NSObject] = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits: 2048 as NSObject,
                kSecReturnPersistentRef: true as NSObject
            ]
            
            var error: Unmanaged<CFError>?
            
            let _privateSecKey: SecKey = SecKeyCreateWithData(_privatekeyData as CFData, keyDictionary as CFDictionary, nil)!
            
            if error != nil {
                print(error ?? "Error in Signed Process")
                completion(nil)
                return
            }

            guard let signedText = self.signUsingPrivate(text, _privateSecKey) else {
                completion(nil)
                return
            }
            completion(signedText)
            return
        }
    }
}

//MARK: - Sign the given text
extension KeyHelper {
    private func signUsingPrivate(_ text: String, _ key: SecKey) -> String? {
        var digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        let data = text.data(using: .utf8)!

        let _ = digest.withUnsafeMutableBytes { digestBytes in
            data.withUnsafeBytes { dataBytes in
                CC_SHA256(dataBytes, CC_LONG(data.count), digestBytes)
            }
        }

        var signature = Data(count: SecKeyGetBlockSize(key) * 4)
        var signatureLength = signature.count

        let result = signature.withUnsafeMutableBytes { signatureBytes in
            digest.withUnsafeBytes { digestBytes in
                SecKeyRawSign(key,
                              SecPadding.PKCS1SHA256,
                              digestBytes,
                              digest.count,
                              signatureBytes,
                              &signatureLength)
            }
        }

        let count = signature.count - signatureLength
        signature.removeLast(count)

        guard result == noErr else {
            print("Error Occured")
            return nil
        }
        return signature.base64EncodedString()
    }
}

