//
//  Push.swift
//  Push
//
//  Created by Brandon Anthony on 2019-05-21.
//  Copyright © 2019 SO. All rights reserved.
//

import Foundation
import Security
import openssl

extension Push {
    public static func setup() {
        SSL_library_init()
        SSL_load_error_strings()
        OPENSSL_add_all_algorithms_noconf()
    }
    
    public static func cleanup() {
        ERR_free_strings()
        EVP_cleanup()
        CRYPTO_cleanup_all_ex_data()
    }
}

public struct Push {
    private let key: Key
    private let bundleId: String
    private let keyId: String
    private let teamId: String
    private let isProduction: Bool
    private let authenticator: PushAuthenticator
    
    public init(bundleId: String, keyId: String, teamId: String, key: Key, isProduction: Bool) {
        self.bundleId = bundleId
        self.keyId = keyId
        self.teamId = teamId
        self.isProduction = isProduction
        self.key = key
        self.authenticator = PushAuthenticator(key: key)
    }
    
    public func push(deviceId: String, payload: [String: Any], _ completion: ((Error?) -> Void)?) {
        do {
            var request = URLRequest(url: URL(string: self.baseURL(deviceId))!)
            request.httpMethod = "POST"
            request.allHTTPHeaderFields = [
                "apns-id": UUID().uuidString,
                "apns-topic": bundleId,
                "apns-priority": "10",
                "apns-expiration": "0"
            ]
            
            if self.key.canSign() {
                request.addValue("bearer \(try self.generateJwtToken())", forHTTPHeaderField: "authorization")
            }
            
            request.httpBody = try JSONSerialization.data(withJSONObject: payload, options: .prettyPrinted)
            
            URLSession(configuration: .ephemeral, delegate: self.authenticator, delegateQueue: .main).dataTask(with: request) { data, response, error in
                
                if let error = error {
                    completion?(error)
                }
                
                if let data = data {
                    debugPrint(String(data: data, encoding: .utf8)!)
                }
            }.resume()
        } catch let error {
            debugPrint(error)
        }
    }
    
    private func baseURL(_ deviceId: String) -> String {
        if isProduction {
            return "https://api.push.apple.com:443/3/device/\(deviceId)"
        }
        
        return "https://api.sandbox.push.apple.com:443/3/device/\(deviceId)"
    }
    
    private func generateJwtToken() throws -> String {
        let timeInterval = Int(Date().timeIntervalSince1970)
        
        let header = [
            "alg": "ES256",
            "kid": self.keyId
        ]
        
        let body = [
            "iss": self.teamId,
            "iat": "\(timeInterval)"
        ]
        
        func base64Encode(_ payload: [String: Any]) throws -> String {
            return try JSONSerialization.data(withJSONObject: payload, options: .init(rawValue: 0)).base64EncodedString()
        }
        
        let part = "\(try base64Encode(header)).\(try base64Encode(body))"
        let signature = try key.sign(part.data(using: .utf8)!).base64EncodedString()
        return "\(part).\(signature)"
    }
    
    private class PushAuthenticator: NSObject, URLSessionDelegate {
        private let key: Key
        init(key: Key) {
            self.key = key
            super.init()
        }
        
        public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust || challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
                do {
                    return completionHandler(.useCredential, try self.key.validate())
                } catch let error {
                    debugPrint(error)
                }
            }

            completionHandler(.performDefaultHandling, nil)
        }
    }
}
