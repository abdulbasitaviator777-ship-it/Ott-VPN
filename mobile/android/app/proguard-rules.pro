# Android specific ProGuard rules for OTT VPN

# Keep Kotlin coroutines
-keep class kotlinx.coroutines.** { *; }

# Keep Retrofit API models (Gson uses reflection)
-keep class com.ottvpn.api.** { *; }
-keep class com.ottvpn.api.ModelsKt { *; }

# Keep WireGuard config parsing
-keep class com.ottvpn.** { *; }

# Keep AuthManager encrypted storage
-dontwarn com.ottvpn.auth.**

# Suppress warnings for missing optional dependencies
-dontwarn kotlinx.**
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn org.apache.commons.**
-dontwarn retrofit2.**
-dontwarn com.google.gson.**
-dontwarn com.google.crypto.**
