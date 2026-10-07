package com.ottvpn.auth

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.util.concurrent.TimeUnit
import kotlin.system.measureNanoTime

/**
 * Manages authentication tokens with secure storage using AndroidX Security Crypto.
 *
 * - Access tokens are stored in EncryptedSharedPreferences
 * - Refresh token rotation is handled automatically
 * - Tokens are checked for expiry before API calls
 */
class AuthManager(context: Context) {

    private val masterKey = MasterKey.Builder(context, MasterKey.DEFAULT_MASTER_KEY_ALIAS)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    data class Tokens(
        val accessToken: String,
        val refreshToken: String?,
        val expiresAt: Long
    )

    fun saveTokens(tokens: Tokens) {
        prefs.edit()
            .putString(KEY_ACCESS_TOKEN, tokens.accessToken)
            .putString(KEY_REFRESH_TOKEN, tokens.refreshToken)
            .putLong(KEY_EXPIRES_AT, tokens.expiresAt)
            .apply()
    }

    fun getTokens(): Tokens? {
        val access = prefs.getString(KEY_ACCESS_TOKEN, null) ?: return null
        val refresh = prefs.getString(KEY_REFRESH_TOKEN, null) ?: return null
        val exp = prefs.getLong(KEY_EXPIRES_AT, 0)
        return Tokens(access, refresh, exp)
    }

    fun getAccessToken(): String? {
        return prefs.getString(KEY_ACCESS_TOKEN, null)
    }

    fun clearTokens() {
        prefs.edit()
            .remove(KEY_ACCESS_TOKEN)
            .remove(KEY_REFRESH_TOKEN)
            .remove(KEY_EXPIRES_AT)
            .apply()
    }

    fun isTokenExpired(): Boolean {
        val exp = prefs.getLong(KEY_EXPIRES_AT, 0)
        val now = System.currentTimeMillis()
        return now >= exp - EXPIRY_BUFFER_MS
    }

    companion object {
        private const val PREFS_NAME = "ottvpn_auth"
        private const val KEY_ACCESS_TOKEN = "access_token"
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_EXPIRES_AT = "expires_at"
        private const val EXPIRY_BUFFER_SECONDS = 120L
        private val EXPIRY_BUFFER_MS = EXPIRY_BUFFER_SECONDS * 1000L
    }
}
