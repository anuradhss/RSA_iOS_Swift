//
//  ViewController.swift
//  RSA_iOS_Swift
//
//  Created by Anuradh Caldera on 12/2/19.
//  Copyright © 2019 https://www.linkedin.com/in/anuradhcaldera/. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    
    private var signedPayload: String?
    private var signedStatus: Bool?
    
    init() {
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        generateKeyPairAndSignWithPrivateKey { [weak self] status in
            self?.signedStatus = status
            print("Signing Process : ", self?.signedStatus ?? false)
            return
        }
    }
}

//MARK: - Generate Key Pair and Sign With Private Key
extension ViewController {
    func generateKeyPairAndSignWithPrivateKey(completion: @escaping(Bool) -> ()) {
        
        generateKeyPair { [weak self] (_pubKey, _priKey) in
            
            if _pubKey != nil && _priKey != nil {
                self?.signWithPrivateKey(privatekeyString: _priKey!, completion: { [weak self] _signed in
                    
                    if _signed != nil {
                        self?.signedPayload = _signed
                        print("Signed : ", self?.signedPayload ?? " ")
                        completion(true)
                        return
                    }
                    print("Error Occured While Signing With Private Key")
                    completion(false)
                    return
                })
                return
            }
            print("Error Occured While Generating Key Pair")
            completion(false)
            return
        }
        return
    }
}

// MARK: - Use of generating key pair by invokine generate key pair method in KyeHelper
extension ViewController {
    
    private func generateKeyPair(completion: @escaping(String?, String?) ->()) {
        
        var _keyhelper = KeyHelper()
        
        _keyhelper.generateRSAKeyPair(length: 2048, completion: { (_publickKey, _privateKey) in
            
            if _publickKey != nil && _privateKey != nil {
                completion(_publickKey, _privateKey)
                return
            }
            completion(nil, nil)
            return
        })
        return
    }
}

//MARK: - Sign With Private Key
extension ViewController {
    private func signWithPrivateKey(privatekeyString: String, completion: @escaping(String?) ->()) {
        
        let _keyhelper = KeyHelper()
        
        _keyhelper.signTextWithPrivateKey(key: privatekeyString, withtext: "Hello Anuradh", completion: { (_signed) in
            
            if _signed != nil {
                completion(_signed)
                return
            }
            completion(nil)
            return
        })
        return
    }
}
