import UIKit
import NetworkExtension

/**
 * Main VPN control screen.
 * Provides connect/disconnect, server selection, and status monitoring.
 */
class MainViewController: UIViewController {

    private let vpnManager = OTTVPNManager.shared
    private var is_connected: Bool = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        setupUI()
    }

    private func setupUI() {
        let connectButton = UIButton(type: .system)
        connectButton.setTitle("CONNECT", for: .normal)
        connectButton.titleLabel?.font = UIFont.preferredFont(forTextStyle: .title2)
        connectButton.backgroundColor = .systemBlue
        connectButton.setTitleColor(.white, for: .normal)
        connectButton.layer.cornerRadius = 12
        connectButton.addTarget(self, action: #selector(toggleVPN), for: .touchUpInside)

        let statusLabel = UILabel()
        statusLabel.text = "NOT CONNECTED"
        statusLabel.font = UIFont.preferredFont(forTextStyle: .title3)
        statusLabel.textAlignment = .center

        let vStack = UIStackView(arrangedSubviews: [statusLabel, connectButton])
        vStack.axis = .vertical
        vStack.spacing = 24
        vStack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(vStack)

        NSLayoutConstraint.activate([
            vStack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            vStack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            connectButton.widthAnchor.constraint(equalToConstant: 280),
            connectButton.heightAnchor.constraint(equalToConstant: 64),
        ])
    }

    @objc private func toggleVPN() {
        if is_connected {
            vpnManager.disconnect()
            is_connected = false
        } else {
            do {
                try vpnManager.connect()
                is_connected = true
            } catch {
                print("VPN start error: \(error)")
            }
        }
    }
}
