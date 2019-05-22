//
//  Signer.swift
//  Signer
//
//  Created by Brandon Anthony on 2019-05-21.
//  Copyright © 2019 SO. All rights reserved.
//

import Foundation
import Security
import CommonCrypto
import openssl

public struct RuntimeError: Error {
    private let message: String
    
    public init(_ message: String) {
        self.message = message
    }
    
    var localizedDescription: String {
        return message
    }
}

public struct Key {
    private let pKey: EVP_PKEY?
    private let identity: SecIdentity?
    private let certificate: SecCertificate?
    
    public static func loadCertificate(_ path: String, passPhrase: String? = nil) throws -> Key {
        let pkcs12_data: Data = try Data(contentsOf: URL(fileURLWithPath: path))
        
        let options = (passPhrase ?? "").isEmpty ? [:] : [kSecImportExportPassphrase: passPhrase ?? ""]
        var items: CFArray? = nil
        var certificate: SecCertificate? = nil
        
        var status = SecPKCS12Import(pkcs12_data as CFData, options as CFDictionary, &items)
        if status != errSecSuccess {
            if let message = SecCopyErrorMessageString(status, nil) {
                throw RuntimeError(message as String)
            }
            throw RuntimeError("Cannot Import PKCS12")
        }
        
        guard let itemsArray = items else {
            throw RuntimeError("No Items in Certificate")
        }
        
        guard let identityAndTrust = (itemsArray as [AnyObject]).first as? [String: AnyObject] else {
            throw RuntimeError("No Identity or Trust found")
        }
        
        let identity = identityAndTrust[kSecImportItemIdentity as String] as! SecIdentity
        status = SecIdentityCopyCertificate(identity, &certificate)
        if status != errSecSuccess {
            if let message = SecCopyErrorMessageString(status, nil) {
                throw RuntimeError(message as String)
            }
            throw RuntimeError("Cannot Copy Identity")
        }
        
        return Key(pKey: nil, identity: identity, certificate: certificate)
    }
    
    public static func loadPKCS8(_ path: String) throws -> Key {
        let bio = BIO_new_file(path, "rb")
        var privateKey: UnsafeMutablePointer<EVP_PKEY>? = nil
        PEM_read_bio_PrivateKey(bio, &privateKey, nil, nil)
        BIO_free(bio)
        return Key(pKey: privateKey?.pointee, identity: nil, certificate: nil)
    }
    
    public func canSign() -> Bool {
        return self.pKey != nil
    }
    
    public func canValidate() -> Bool {
        return self.identity != nil && self.certificate != nil
    }
    
    public func validate() throws -> URLCredential {
        guard let identity = self.identity, let certificate = self.certificate else {
            throw RuntimeError("Cannot Verify Host with P12 Certificate")
        }
        
        return URLCredential(identity: identity, certificates: [certificate], persistence: .forSession)
    }
    
    public func sign(_ data: Data) throws -> Data {
        guard var pKey = self.pKey else {
            throw RuntimeError("Invalid EC Private Key")
        }
        
        let ctx = EVP_MD_CTX_create()
        let md = EVP_get_digestbyname(SN_ecdsa_with_SHA256) ?? EVP_get_digestbyname(SN_sha256)
        EVP_DigestInit_ex(ctx, md, nil)
        EVP_DigestSignInit(ctx, nil, md, nil, &pKey)
        _ = data.withUnsafeBytes({
            EVP_DigestUpdate(ctx, $0.baseAddress, data.count)
        })
        
        var sigLen = 0
        EVP_DigestSignFinal(ctx, nil, &sigLen)
        
        var signature = [UInt8](repeating: 0x00, count: sigLen)
        EVP_DigestSignFinal(ctx, &signature, &sigLen)
        EVP_MD_CTX_destroy(ctx)
        return Data(signature)
    }
}
