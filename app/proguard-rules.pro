# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.

# Keep detection classes
-keep class com.anycheck.app.detection.** { *; }

# Keep Kotlin data classes
-keepclassmembers class * {
    @kotlin.Metadata *;
}

# Compose
-dontwarn androidx.compose.**
