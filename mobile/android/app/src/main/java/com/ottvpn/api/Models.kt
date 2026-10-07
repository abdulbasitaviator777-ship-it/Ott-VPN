package com.ottvpn.api

import com.google.gson.annotations.SerializedName

/**
 * Data models matching the OTT VPN backend API schemas.
 * See backend/api/schemas.py for the canonical definitions.
 */

data class ServerInfo(
    @SerializedName("id") val id: String,
    @SerializedName("city") val city: String,
    @SerializedName("country") val country: String,
    @SerializedName("region") val region: String?,
    @SerializedName("latency_ms") val latencyMs: Double?,
    @SerializedName("load_percent") val loadPercent: Double?,
    @SerializedName("status") val status: String,
    @SerializedName("latitude") val latitude: Double?,
    @SerializedName("longitude") val longitude: Double?,
    @SerializedName("ott_zee5") val ottZee5: String?,
    @SerializedName("ott_jiohotstar") val ottJiohotstar: String?,
    @SerializedName("wireguard_port") val wireguardPort: Int?
)

data class ServerDetail(
    @SerializedName("id") val id: String,
    @SerializedName("city") val city: String,
    @SerializedName("country") val country: String,
    @SerializedName("region") val region: String?,
    @SerializedName("latency_ms") val latencyMs: Double?,
    @SerializedName("load_percent") val loadPercent: Double?,
    @SerializedName("status") val status: String,
    @SerializedName("latitude") val latitude: Double?,
    @SerializedName("longitude") val longitude: Double?,
    @SerializedName("hostname") val hostname: String?,
    @SerializedName("ipv4") val ipv4: String?,
    @SerializedName("ipv6") val ipv6: String?,
    @SerializedName("wireguard_pubkey") val wireguardPubkey: String?,
    @SerializedName("wireguard_net") val wireguardNet: String?,
    @SerializedName("wireguard_net6") val wireguardNet6: String?,
    @SerializedName("protocol") val protocol: String?,
    @SerializedName("capacity") val capacity: Int?,
    @SerializedName("current_peers") val currentPeers: Int?,
    @SerializedName("dns_ok") val dnsOk: Boolean?,
    @SerializedName("ipv6_ok") val ipv6Ok: Boolean?,
    @SerializedName("preshared_key") val presharedKey: Boolean?
)

data class ServerListResponse(
    @SerializedName("country") val country: String,
    @SerializedName("servers") val servers: List<ServerInfo>
)

data class TokenResponse(
    @SerializedName("access_token") val accessToken: String,
    @SerializedName("refresh_token") val refreshToken: String? = null,
    @SerializedName("token_type") val tokenType: String = "bearer",
    @SerializedName("expires_in") val expiresIn: Int
)

data class LoginResponse(
    @SerializedName("access_token") val accessToken: String,
    @SerializedName("refresh_token") val refreshToken: String? = null,
    @SerializedName("token_type") val tokenType: String = "bearer",
    @SerializedName("expires_in") val expiresIn: Int
)

data class VpnConfigResponse(
    @SerializedName("server_id") val serverId: String,
    @SerializedName("config") val config: String,
    @SerializedName("expires_at") val expiresAt: String
)

data class VpnStatusResponse(
    @SerializedName("connected") val connected: Boolean,
    @SerializedName("server") val server: ServerInfo?,
    @SerializedName("tunnel_ip") val tunnelIp: String?,
    @SerializedName("public_ip") val publicIp: String?,
    @SerializedName("dns_protected") val dnsProtected: Boolean?,
    @SerializedName("ipv6_protected") val ipv6Protected: Boolean?,
    @SerializedName("bytes_tx") val bytesTx: Long?,
    @SerializedName("bytes_rx") val bytesRx: Long?
)
