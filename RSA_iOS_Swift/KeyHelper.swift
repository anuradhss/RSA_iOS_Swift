//
//  KeyHelper.swift
//  RSA_iOS_Swift
//
//  Created by Anuradh Caldera on 12/2/19.
//  Copyright © 2019 https://www.linkedin.com/in/anuradhcaldera/. All rights reserved.
//

import Foundation

struct KeyHelper {
    private var osstatus: OSStatus?
    private var publickey: SecKey?
    private var privatekey: SecKey?
}

extension KeyHelper {
    
    mutating func generateRSAKeyPair(length: Int) {
        
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
        }
        
        
    }
}
