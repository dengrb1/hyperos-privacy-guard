package com.hyperos.privacyguard

data class SystemComponent(
    val packageName: String,
    val label: String,
    val uid: Int,
    val versionName: String,
    val versionCode: Long,
    val category: String,
    val isSystem: Boolean,
    val permissions: Set<String>,
    val signatureSha256: String,
) {
    val permissionFingerprint: String
        get() = permissions.sorted().joinToString("\u0000")

    val requestsUsageStats: Boolean
        get() = "android.permission.PACKAGE_USAGE_STATS" in permissions

    val privacySignals: List<String>
        get() = buildList {
            if (requestsUsageStats) add("应用活动记录")
            if (permissions.any { it in DEVICE_ID_PERMISSIONS }) add("设备标识")
            if (permissions.any { it in LOCATION_PERMISSIONS }) add("位置")
            if (permissions.any { it in CONTACT_PERMISSIONS }) add("联系人")
            if (permissions.any { it in CALL_OR_SMS_PERMISSIONS }) add("通话与短信")
            if (permissions.any { it in MEDIA_PERMISSIONS }) add("麦克风/相机/媒体")
            if (permissions.any { it in CONTROL_PERMISSIONS }) add("屏幕覆盖/辅助功能")
        }

    companion object {
        val DEVICE_ID_PERMISSIONS = setOf(
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.READ_PRIVILEGED_PHONE_STATE",
        )
        val LOCATION_PERMISSIONS = setOf(
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
        )
        val CONTACT_PERMISSIONS = setOf(
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
        )
        val CALL_OR_SMS_PERMISSIONS = setOf(
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
        )
        val MEDIA_PERMISSIONS = setOf(
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_EXTERNAL_STORAGE",
        )
        val CONTROL_PERMISSIONS = setOf(
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        )
    }
}

data class GuardRule(
    val packageName: String,
    val enabled: Boolean = false,
    val backupMode: String? = null,
    val permissionFingerprint: String? = null,
    val lastObservedMode: String? = null,
    val lastError: String? = null,
    val lastChangedAt: Long? = null,
)

data class OperationLog(
    val timestamp: Long,
    val title: String,
    val detail: String,
    val success: Boolean,
)

data class CompatibilityInfo(
    val api: Int,
    val release: String,
    val supported: Boolean,
    val reason: String,
)

data class GuardState(
    val components: List<SystemComponent> = emptyList(),
    val rules: Map<String, GuardRule> = emptyMap(),
    val logs: List<OperationLog> = emptyList(),
    val observedModes: Map<String, String> = emptyMap(),
    val installedShizuku: Boolean = false,
    val binderAlive: Boolean = false,
    val authorized: Boolean = false,
    val scanning: Boolean = false,
    val lastCheckAt: Long? = null,
    val filter: String = "",
    val selectedCategory: String = "全部",
    val theme: String = "system",
    val message: String? = null,
    val isBusy: Boolean = false,
    val compatibility: CompatibilityInfo = CompatibilityInfo(
        api = android.os.Build.VERSION.SDK_INT,
        release = android.os.Build.VERSION.RELEASE ?: "未知",
        supported = android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M,
        reason = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            "支持 PACKAGE_USAGE_STATS AppOps 审计"
        } else {
            "Android 6.0 以下不支持此项 AppOps 审计"
        },
    ),
)

enum class GuardPage(val label: String, val usageKey: String) {
    HOME("首页", "home"), PROTECTION("活动记录", "protection"), AUDIT("活动审计", "audit"),
    COMPONENTS("系统组件", "components"), PERMISSIONS("权限管理", "permissions"),
    LOGS("操作日志", "logs"), RESEARCH("数据研究", "research"), NETWORK("网络审计", "network"),
    SETTINGS("设置", "settings"),
}
