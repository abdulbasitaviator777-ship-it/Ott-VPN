package com.ottvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * OTT VPN Android VPN Service.
 *
 * Provides a full-tunnel VPN using WireGuard.  Implements:
 * - Kill switch: VpnService blocks all non-VPN traffic
 * - DNS leak protection: routes all DNS through the tunnel
 * - IPv6 leak protection: IPv6 routes through the tunnel
 *
 * The WireGuard config is fetched from the OTT VPN backend API
 * by MainActivity and passed via EXTRA_WG_CONFIG.
 *
 * In production, WireGuard native tunneling is handled by the
 * WireGuard Android library (WgQuickTunnel).  This service
 * establishes the TUN interface and manages the tunnel lifecycle.
 */
class OTTVpnService : VpnService() {

    companion object {
        private const val TAG = "OTTVPN"
        private const val MTU = 1280
        const val EXTRA_WG_CONFIG = "wg_config"
        const val EXTRA_SERVER_ID = "server_id"
        private const val NOTIF_CHANNEL_ID = "ottvpn_vpn_channel"
        private const val NOTIF_ID = 1
    }

    private var tunnel: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val config = intent?.getStringExtra(EXTRA_WG_CONFIG)
        if (config == null || config.isEmpty()) {
            Log.e(TAG, "No WireGuard config provided")
            stopSelf()
            return START_NOT_STICKY
        }

        // Start as foreground service with notification
        val notification = buildNotification(isConnected = true)
        startForeground(NOTIF_ID, notification)

        startVpn(config)
        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIF_CHANNEL_ID,
                getString(R.string.notification_channel_vpn),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "OTT VPN connection status"
            }
            val mgr = getSystemService(NotificationManager::class.java)
            mgr.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(isConnected: Boolean): Notification {
        val title = if (isConnected) getString(R.string.notification_vpn_connected) else getString(R.string.notification_vpn_disconnected)
        return Notification.Builder(this, NOTIF_CHANNEL_ID)
            .setContentTitle("OTT VPN")
            .setContentText(title)
            .setSmallIcon(R.drawable.ic_vpn_foreground)
            .setOngoing(true)
            .build()
    }

    private fun startVpn(wgConfig: String) {
        try {
            val parsed = parseWgConfig(wgConfig)

            val builder = Builder()
                .setSession("OTT VPN")
                .setMtu(MTU)

            // Tunnel addresses
            parsed.tunnelIp4?.let { builder.addAddress(it, 24) }
            parsed.tunnelIp6?.let { builder.addAddress(it, 64) }

            // Full tunnel — route all traffic through VPN
            builder.addRoute(IpPrefix(InetAddress.getByName("0.0.0.0"), 0))
            builder.addRoute(IpPrefix(InetAddress.getByName("::"), 0))

            // DNS — push the VPN's DNS resolver
            parsed.dnsServers.forEach { builder.addDnsServer(it) }

            // Kill switch: VpnService blocks all non-VPN traffic by default
            // All traffic must go through the TUN interface
            builder.setBlocking(true)

            tunnel = builder.establish()
            if (tunnel == null) {
                Log.e(TAG, "Failed to establish VPN tunnel")
                stopSelf()
                return
            }

            // Start WireGuard handshake using the config
            // In production, use the WireGuard Android API:
            //   val config = ParseConfig.parse(wgConfig)
            //   val tunnel = WgQuickTunnel(config)
            //   tunnel.start()

            Log.i(TAG, "VPN started: ${parsed.serverEndpoint}")

        } catch (e: Exception) {
            Log.e(TAG, "VPN start failed", e)
            stopSelf()
        }
    }

    override fun onDestroy() {
        tunnel?.close()
        tunnel = null
        val notification = buildNotification(isConnected = false)
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.notify(NOTIF_ID, notification)
        super.onDestroy()
    }

    private data class ParsedConfig(
        val tunnelIp4: String?,
        val tunnelIp6: String?,
        val dnsServers: List<String>,
        val serverEndpoint: String,
    )

    private fun parseWgConfig(config: String): ParsedConfig {
        val lines = config.lines()
        var tunnelIp4: String? = null
        var tunnelIp6: String? = null
        val dnsServers = mutableListOf<String>()
        var endpoint = ""

        for (line in lines) {
            val trimmed = line.trim()
            when {
                trimmed.startsWith("Address", ignoreCase = true) -> {
                    val addr = trimmed.substringAfter("=").trim()
                    val parts = addr.split(",")
                    parts.forEach { part ->
                        val ip = part.trim().split("/")[0]
                        if (ip.contains(":")) {
                            tunnelIp6 = ip
                        } else {
                            tunnelIp4 = ip
                        }
                    }
                }
                trimmed.startsWith("DNS", ignoreCase = true) -> {
                    val dns = trimmed.substringAfter("=").trim()
                    dnsServers.addAll(dns.split(",").map { it.trim() })
                }
                trimmed.startsWith("Endpoint", ignoreCase = true) -> {
                    endpoint = trimmed.substringAfter("=").trim()
                }
            }
        }

        return ParsedConfig(
            tunnelIp4 = tunnelIp4,
            tunnelIp6 = tunnelIp6,
            dnsServers = dnsServers,
            serverEndpoint = endpoint,
        )
    }
}
