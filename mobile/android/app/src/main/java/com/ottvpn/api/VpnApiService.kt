package com.ottvpn.api

import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

/**
 * OTT VPN Backend API Service.
 *
 * All endpoints match the backend FastAPI routers:
 *   Auth:      POST /api/auth/register | login | refresh | logout
 *   Servers:   GET  /api/servers/ | /recommended | /{id}
 *   VPN:       POST /api/vpn/config | revoke | GET /status | GET /configs
 */
interface VpnApiService {

    // === Auth ===
    suspend fun register(
        email: String,
        password: String,
        deviceInfo: String = "android"
    ): LoginResponse

    suspend fun login(
        email: String,
        password: String,
        deviceInfo: String = "android"
    ): LoginResponse

    suspend fun refresh(refreshToken: String): LoginResponse

    suspend fun logout(refreshToken: String): Map<String, String>

    // === Servers ===
    suspend fun listServers(country: String = "IN", city: String? = null): ServerListResponse

    suspend fun recommendServers(limit: Int = 5): List<ServerInfo>

    suspend fun getServer(serverId: String): ServerDetail

    // === VPN ===
    suspend fun generateConfig(serverId: String? = null, splitTunnel: Boolean = false): VpnConfigResponse

    suspend fun revokeConfig(peerId: String): Map<String, String>

    suspend fun getVpnStatus(): VpnStatusResponse

    suspend fun listConfigs(): List<Map<String, Any>>

    companion object {
        private const val BASE_URL = "https://api.ottvpn.in"

        fun create(accessToken: String? = null): VpnApiService {
            return create(BASE_URL, accessToken)
        }

        fun create(baseUrl: String, accessToken: String? = null): VpnApiService {
            val authInterceptor = AuthInterceptor(accessToken)
            val logging = HttpLoggingInterceptor().apply {
                level = HttpLoggingInterceptor.Level.BODY
            }

            val client = OkHttpClient.Builder()
                .addInterceptor(authInterceptor)
                .addInterceptor(logging)
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build()

            val retrofit = Retrofit.Builder()
                .baseUrl(baseUrl)
                .client(client)
                .addConverterFactory(GsonConverterFactory.create())
                .build()

            return VpnApiServiceImpl(retrofit)
        }
    }
}

/** Adds the Authorization header if a token is provided. */
private class AuthInterceptor(private val token: String?) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request().newBuilder()
        if (!token.isNullOrEmpty()) {
            request.addHeader("Authorization", "Bearer $token")
        }
        return chain.proceed(request.build())
    }
}
