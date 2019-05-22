//
//  ViewController.swift
//  PushServer-iOS
//
//  Created by Brandon Anthony on 2019-05-21.
//  Copyright © 2019 SO. All rights reserved.
//

import UIKit
import Push

class ViewController: UIViewController {
    
    private static let bundleId = "<#Bundle ID Or Some Topic Here#>"
    private static let keyId = "<#KeyID Or Some Other ID Here#>"
    private static let teamId = "<#TeamID Or Some Other ID Here#>"
    private static let deviceId = "<#Device ID Here#>"
    private static let payload = [
        "aps": [
            "alert": [
                "title": "Notification Title",
                "body": "Notification Body"
            ]
        ]
    ]
    
    override init(nibName nibNameOrNil: String?, bundle nibBundleOrNil: Bundle?) {
        super.init(nibName: nibNameOrNil, bundle: nibBundleOrNil)
        
        Push.setup()
    }
    
    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    deinit {
        Push.cleanup()
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.backgroundColor = .white
    
        let button = UIButton()
        button.backgroundColor = .red
        button.setTitle("Push", for: .normal)
        button.setTitleColor(.white, for: .normal)
        
        self.view.addSubview(button)
        NSLayoutConstraint.activate([
            button.leftAnchor.constraint(greaterThanOrEqualTo: view.leftAnchor, constant: 15.0),
            button.rightAnchor.constraint(lessThanOrEqualTo: view.rightAnchor, constant: -15.0),
            button.topAnchor.constraint(greaterThanOrEqualTo: view.safeAreaLayoutGuide.topAnchor, constant: 15.0),
            button.bottomAnchor.constraint(lessThanOrEqualTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -15.0),
            
            button.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            button.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            
            button.widthAnchor.constraint(equalToConstant: 100.0),
            button.heightAnchor.constraint(equalToConstant: 50.0)
        ])
        
        button.translatesAutoresizingMaskIntoConstraints = false
        
        button.addTarget(self, action: #selector(onButtonPressed(_:)), for: .touchUpInside)
    }
    
    private func pushCert() {
        do {
            let certPath = Bundle.main.path(forResource: "Certificates", ofType: "p12")
            let push = Push(bundleId: ViewController.bundleId,
                            keyId: ViewController.keyId,
                            teamId: ViewController.teamId,
                            key: try Key.loadCertificate(certPath!, passPhrase: "1234"),
                            isProduction: false)
            
            push.push(deviceId: ViewController.deviceId, payload: ViewController.payload) { error in
                if let error = error {
                    debugPrint(error)
                }
            }
        } catch let error {
            debugPrint(error)
        }
    }
    
    private func pushP8() {
        do {
            let certPath = Bundle.main.path(forResource: "Certificates", ofType: "p12")
            let push = Push(bundleId: ViewController.bundleId,
                            keyId: ViewController.keyId,
                            teamId: ViewController.teamId,
                            key: try Key.loadPKCS8(certPath!),
                            isProduction: false)
            
            push.push(deviceId: ViewController.deviceId, payload: ViewController.payload) { error in
                if let error = error {
                    debugPrint(error)
                }
            }
        } catch let error {
            debugPrint(error)
        }
    }
    
    @objc
    private func onButtonPressed(_ button: UIButton) {
        pushCert()
    }
}

