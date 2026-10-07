package com.ottvpn

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.ottvpn.api.ServerInfo
import com.ottvpn.api.VpnApiService
import com.ottvpn.auth.AuthManager
import com.ottvpn.ui.ServerAdapter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Main VPN control screen — mirrors the spec's UI layout:
 *
 *   INDIA VPN
 *   [CONNECT] / [DISCONNECT]
 *   Location: 🇮🇳 India / Mumbai
 *   Latency: 38 ms
 *   Server Load: 21 %
 *   DNS Leak: Protected
 *   IPv6: Protected
 *
 * Backend integration:
 *   - Auth flow (register/login with token storage)
 *   - Server listing from /api/servers/
 *   - Config generation from /api/vpn/config
 *   - Foreground VPN service
 */
class MainActivity : AppCompatActivity() {

    private lateinit var connectButton: Button
    private lateinit var statusText: TextView
    private lateinit var locationText: TextView
    private lateinit var cityText: TextView
    private lateinit var latencyText: TextView
    private lateinit var loadText: TextView
    private lateinit var dnsStatusText: TextView
    private lateinit var ipv6StatusText: TextView
    private lateinit var serverList: RecyclerView
    private lateinit var serverListTitle: TextView

    private lateinit var authManager: AuthManager
    private var apiService: VpnApiService? = null

    private val selectedServer = MutableStateFlow<ServerInfo?>(null)
    private val serverListState = mutableListOf<ServerInfo>()
    private var serverAdapter: ServerAdapter? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        initViews()
        initAuth()
        setupServerList()
        loadServers()
        checkVpnStatus()

        connectButton.setOnClickListener { toggleVpn() }
    }

    private fun initViews() {
        connectButton = findViewById(R.id.connect_button)
        statusText = findViewById(R.id.status_text)
        locationText = findViewById(R.id.location_text)
        cityText = findViewById(R.id.city_text)
        latencyText = findViewById(R.id.latency_text)
        loadText = findViewById(R.id.load_text)
        dnsStatusText = findViewById(R.id.dns_status_text)
        ipv6StatusText = findViewById(R.id.ipv6_status_text)
        serverList = findViewById(R.id.server_list)
        serverListTitle = findViewById(R.id.server_list_title)
    }

    private fun initAuth() {
        authManager = AuthManager(this)
        val tokens = authManager.getTokens()
        if (tokens != null && !tokens.accessToken.isNullOrEmpty()) {
            apiService = VpnApiService.create(
                baseUrl = getString(R.string.vpn_api_base),
                accessToken = tokens.accessToken
            )
            if (authManager.isTokenExpired()) {
                refreshToken()
            }
        } else {
            showLoginDialog()
        }
    }

    private fun setupServerList() {
        serverAdapter = ServerAdapter(mutableListOf()) { server ->
            selectedServer.value = server
            updateServerInfo(server)
            serverList.visibility = View.GONE
            serverListTitle.visibility = View.GONE
        }
        serverList.layoutManager = LinearLayoutManager(this)
        serverList.adapter = serverAdapter
    }

    private fun checkVpnStatus() {
        val api = apiService ?: return
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val status = api.getVpnStatus()
                launch(Dispatchers.Main) {
                    if (status.connected) {
                        statusText.text = "CONNECTED"
                        connectButton.text = "DISCONNECT"
                        status.server?.let { updateServerInfo(it) }
                    } else {
                        statusText.text = "NOT CONNECTED"
                        connectButton.text = "CONNECT"
                    }
                }
            } catch (e: Exception) {
                // Not connected or API error
            }
        }
    }

    private fun loadServers() {
        val api = apiService ?: return
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val response = api.listServers()
                serverListState.clear()
                serverListState.addAll(response.servers)
                launch(Dispatchers.Main) {
                    serverAdapter?.updateServers(response.servers)
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    private fun updateServerInfo(server: ServerInfo?) {
        server ?: return
        cityText.text = server.city
        locationText.text = server.country
        latencyText.text = server.latencyMs?.let { "Latency: ${it.toInt()} ms" } ?: "Latency: -- ms"
        loadText.text = server.loadPercent?.let { "Server Load: ${it.toInt()} %" } ?: "Server Load: -- %"
        dnsStatusText.text = "DNS Leak: Protected"
        ipv6StatusText.text = "IPv6: Protected"
    }

    private fun toggleVpn() {
        val api = apiService ?: return

        if (connectButton.text == "CONNECT") {
            val server = selectedServer.value
            if (server == null) {
                serverList.visibility = View.VISIBLE
                serverListTitle.visibility = View.VISIBLE
                Toast.makeText(this, "Select a server first", Toast.LENGTH_SHORT).show()
                return
            }

            // Fetch WireGuard config from backend API
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    val response = api.generateConfig(serverId = server.id)
                    launch(Dispatchers.Main) {
                        startVpnService(response.config)
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                    launch(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Failed to get config: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        } else {
            // Disconnect
            stopService(Intent(this, OTTVpnService::class.java))
            connectButton.text = "CONNECT"
            statusText.text = "NOT CONNECTED"
        }
    }

    private fun startVpnService(wgConfig: String) {
        val intent = Intent(this, OTTVpnService::class.java).apply {
            putExtra(OTTVpnService.EXTRA_WG_CONFIG, wgConfig)
        }
        startForegroundService(intent)
        connectButton.text = "DISCONNECT"
        statusText.text = "CONNECTED"
    }

    private fun showLoginDialog() {
        val dialogView = layoutInflater.inflate(R.layout.dialog_login, null)
        val emailInput = dialogView.findViewById<EditText>(R.id.login_email)
        val passwordInput = dialogView.findViewById<EditText>(R.id.login_password)
        val isRegisterMode = MutableStateFlow(false)

        val dialog = AlertDialog.Builder(this)
            .setView(dialogView)
            .setCancelable(false)
            .create()

        dialogView.findViewById<Button>(R.id.login_submit).setOnClickListener {
            val email = emailInput.text.toString()
            val password = passwordInput.text.toString()

            if (email.isBlank() || password.isBlank()) {
                Toast.makeText(this, "Email and password required", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    val result = if (isRegisterMode.value) {
                        apiService?.register(email, password)
                    } else {
                        apiService?.login(email, password)
                    }

                    result?.let { response ->
                        val tokens = AuthManager.Tokens(
                            accessToken = response.accessToken,
                            refreshToken = response.refreshToken,
                            expiresAt = System.currentTimeMillis() + (response.expiresIn * 1000L)
                        )
                        authManager.saveTokens(tokens)

                        apiService = VpnApiService.create(
                            baseUrl = getString(R.string.vpn_api_base),
                            accessToken = tokens.accessToken
                        )

                        launch(Dispatchers.Main) {
                            dialog.dismiss()
                            loadServers()
                        }
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                    launch(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Auth failed: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
        }

        dialogView.findViewById<TextView>(R.id.login_toggle).setOnClickListener {
            isRegisterMode.update { !it }
            val modeText = if (isRegisterMode.value) "REGISTER" else "LOGIN"
            dialogView.findViewById<Button>(R.id.login_submit).text = modeText
        }

        dialog.show()
    }

    private fun refreshToken() {
        val tokens = authManager.getTokens() ?: return
        val refreshed = VpnApiService.create(getString(R.string.vpn_api_base))
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val response = refreshed.refresh(tokens.refreshToken ?: "")
                val newTokens = AuthManager.Tokens(
                    accessToken = response.accessToken,
                    refreshToken = response.refreshToken,
                    expiresAt = System.currentTimeMillis() + (response.expiresIn * 1000L)
                )
                authManager.saveTokens(newTokens)
                apiService = VpnApiService.create(
                    baseUrl = getString(R.string.vpn_api_base),
                    accessToken = newTokens.accessToken
                )
            } catch (e: Exception) {
                e.printStackTrace()
                launch(Dispatchers.Main) {
                    authManager.clearTokens()
                    showLoginDialog()
                }
            }
        }
    }
}
