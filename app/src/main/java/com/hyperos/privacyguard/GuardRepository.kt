package com.hyperos.privacyguard

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelFileDescriptor
import moe.shizuku.server.IShizukuService
import org.json.JSONArray
import org.json.JSONObject
import rikka.shizuku.Shizuku
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class GuardRepository(context: Context) {
    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences("privacy_guard", Context.MODE_PRIVATE)
    private val packageManager = appContext.packageManager

    fun loadRules(): Map<String, GuardRule> = runCatching {
        val array = JSONArray(prefs.getString("rules", "[]"))
        buildMap {
            for (i in 0 until array.length()) {
                val item = array.getJSONObject(i)
                val name = item.getString("packageName")
                if (!isValidPackageName(name)) continue
                put(name, GuardRule(
                    packageName = name,
                    enabled = item.optBoolean("enabled", false),
                    backupMode = item.optString("backupMode").takeUnless { it == "null" || it.isBlank() },
                    permissionFingerprint = item.optString("permissionFingerprint").takeUnless { it == "null" || it.isBlank() },
                    lastObservedMode = item.optString("lastObservedMode").takeUnless { it == "null" || it.isBlank() },
                    lastError = item.optString("lastError").takeUnless { it == "null" || it.isBlank() },
                    lastChangedAt = item.optLong("lastChangedAt", 0L).takeUnless { it == 0L },
                ))
            }
        }
    }.getOrDefault(emptyMap())

    fun saveRules(rules: Map<String, GuardRule>): Boolean {
        val array = JSONArray()
        rules.values.sortedBy { it.packageName }.forEach { rule ->
            array.put(JSONObject().apply {
                put("packageName", rule.packageName)
                put("enabled", rule.enabled)
                put("backupMode", rule.backupMode ?: JSONObject.NULL)
                put("permissionFingerprint", rule.permissionFingerprint ?: JSONObject.NULL)
                put("lastObservedMode", rule.lastObservedMode ?: JSONObject.NULL)
                put("lastError", rule.lastError ?: JSONObject.NULL)
                put("lastChangedAt", rule.lastChangedAt ?: JSONObject.NULL)
            })
        }
        return prefs.edit().putString("rules", array.toString()).commit()
    }

    fun loadLogs(): List<OperationLog> = runCatching {
        val array = JSONArray(prefs.getString("logs", "[]"))
        (0 until array.length()).map { index ->
            val item = array.getJSONObject(index)
            OperationLog(item.getLong("timestamp"), item.getString("title"), item.getString("detail"), item.getBoolean("success"))
        }.reversed()
    }.getOrDefault(emptyList())

    fun appendLog(log: OperationLog) {
        val prior = loadLogs().asReversed().take(499)
        val array = JSONArray()
        (prior + log).forEach { entry ->
            array.put(JSONObject().apply {
                put("timestamp", entry.timestamp)
                put("title", entry.title)
                put("detail", entry.detail)
                put("success", entry.success)
            })
        }
        prefs.edit().putString("logs", array.toString()).apply()
    }

    fun theme(): String = prefs.getString("theme", "system") ?: "system"
    fun setTheme(value: String) { prefs.edit().putString("theme", value).apply() }

    fun exportConfiguration(): String = JSONObject().apply {
        put("format", CONFIG_FORMAT)
        put("version", 1)
        put("exportedAt", System.currentTimeMillis())
        put("targets", JSONArray().apply {
            loadRules().values.sortedBy { it.packageName }.forEach { rule ->
                put(JSONObject().apply {
                    put("packageName", rule.packageName)
                    // Export is an observation/rule file. It never grants permission to write.
                    put("enabled", false)
                    put("backupMode", JSONObject.NULL)
                    put("permissionFingerprint", rule.permissionFingerprint ?: JSONObject.NULL)
                    put("lastObservedMode", rule.lastObservedMode ?: JSONObject.NULL)
                    put("lastError", rule.lastError ?: JSONObject.NULL)
                    put("lastChangedAt", rule.lastChangedAt ?: JSONObject.NULL)
                })
            }
        })
    }.toString(2)

    fun recordUsage(event: String) {
        val date = SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(System.currentTimeMillis())
        val updated = UsageMetrics.increment(loadUsageMetrics(), date, event)
        val json = JSONObject().apply {
            updated.forEach { (day, events) ->
                put(day, JSONObject().apply { events.forEach { (name, count) -> put(name, count) } })
            }
        }
        prefs.edit().putString("usage_metrics", json.toString()).apply()
    }

    fun clearUsageMetrics() {
        prefs.edit().remove("usage_metrics").apply()
    }

    private fun loadUsageMetrics(): Map<String, Map<String, Int>> = runCatching {
        val root = JSONObject(prefs.getString("usage_metrics", "{}") ?: "{}")
        buildMap {
            val dayKeys = root.keys()
            while (dayKeys.hasNext()) {
                val day = dayKeys.next()
                val events = root.optJSONObject(day) ?: continue
                val eventKeys = events.keys()
                val counts = buildMap {
                    while (eventKeys.hasNext()) {
                        val event = eventKeys.next()
                        val count = events.optInt(event, 0)
                        if (count > 0) put(event, count)
                    }
                }
                if (counts.isNotEmpty()) put(day, counts)
            }
        }
    }.getOrDefault(emptyMap())

    fun exportDiagnostics(state: GuardState): String = JSONObject().apply {
        put("format", DIAGNOSTICS_FORMAT)
        put("version", 1)
        put("exportedAt", System.currentTimeMillis())
        put("app", JSONObject().apply {
            put("packageName", appContext.packageName)
            runCatching {
                val info = if (Build.VERSION.SDK_INT >= 33) {
                    packageManager.getPackageInfo(appContext.packageName, PackageManager.PackageInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    packageManager.getPackageInfo(appContext.packageName, 0)
                }
                put("versionName", info.versionName ?: "未知")
                put("versionCode", if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else {
                    @Suppress("DEPRECATION")
                    info.versionCode.toLong()
                })
            }.onFailure {
                put("versionName", "未观测")
                put("versionCode", JSONObject.NULL)
            }
        })
        put("device", JSONObject().apply {
            put("manufacturer", Build.MANUFACTURER)
            put("brand", Build.BRAND)
            put("model", Build.MODEL)
            put("device", Build.DEVICE)
            put("product", Build.PRODUCT)
            put("androidRelease", Build.VERSION.RELEASE ?: "未知")
            put("sdk", Build.VERSION.SDK_INT)
            put("securityPatch", Build.VERSION.SECURITY_PATCH ?: "未知")
        })
        put("runtime", JSONObject().apply {
            put("shizukuInstalled", state.installedShizuku)
            put("shizukuBinderAlive", state.binderAlive)
            put("shizukuAuthorized", state.authorized)
            put("lastCheckAt", state.lastCheckAt ?: JSONObject.NULL)
            put("theme", state.theme)
            put("compatibility", JSONObject().apply {
                put("api", state.compatibility.api)
                put("release", state.compatibility.release)
                put("supported", state.compatibility.supported)
                put("reason", state.compatibility.reason)
            })
        })
        put("appUsage", JSONObject().apply {
            put("retentionDays", UsageMetrics.RETENTION_DAYS)
            put("dailyCounts", JSONArray().apply {
                loadUsageMetrics().toSortedMap().forEach { (date, events) ->
                    put(JSONObject().apply {
                        put("dateUtc", date)
                        put("events", JSONObject().apply {
                            events.toSortedMap().forEach { (event, count) -> put(event, count) }
                        })
                    })
                }
            })
        })
        put("components", JSONArray().apply {
            state.components.sortedBy { it.packageName }.forEach { component ->
                put(JSONObject().apply {
                    put("packageName", component.packageName)
                    put("label", component.label)
                    put("uid", component.uid)
                    put("versionName", component.versionName)
                    put("versionCode", component.versionCode)
                    put("category", component.category)
                    put("system", component.isSystem)
                    put("requestedPermissions", JSONArray(component.permissions.sorted()))
                    put("privacySignals", JSONArray(component.privacySignals))
                    put("signatureSha256", component.signatureSha256)
                    put("observedUsageStatsMode", state.observedModes[component.packageName]
                        ?: state.rules[component.packageName]?.lastObservedMode
                        ?: JSONObject.NULL)
                    put("lastError", state.rules[component.packageName]?.lastError
                        ?.replace(PACKAGE_REDACTION_PATTERN, "[package]") ?: JSONObject.NULL)
                })
            }
        })
        put("rules", JSONArray().apply {
            state.rules.values.sortedBy { it.packageName }.forEach { rule ->
                put(JSONObject().apply {
                    put("packageName", rule.packageName)
                    put("enabled", rule.enabled)
                    put("legacyBackupMode", rule.backupMode ?: JSONObject.NULL)
                    put("permissionFingerprint", rule.permissionFingerprint ?: JSONObject.NULL)
                    put("lastObservedMode", rule.lastObservedMode ?: JSONObject.NULL)
                    put("lastError", rule.lastError?.replace(PACKAGE_REDACTION_PATTERN, "[package]") ?: JSONObject.NULL)
                    put("lastChangedAt", rule.lastChangedAt ?: JSONObject.NULL)
                })
            }
        })
        put("logs", JSONArray().apply {
            state.logs.take(100).forEach { log ->
                put(JSONObject().apply {
                    put("timestamp", log.timestamp)
                    put("title", log.title)
                    put("detail", log.detail.replace(PACKAGE_REDACTION_PATTERN, "[package]"))
                    put("success", log.success)
                })
            }
        })
        put("privacyBoundary", JSONArray(listOf(
            "应用页面和功能操作按 UTC 日期累计；仅保留最近 ${UsageMetrics.RETENTION_DAYS} 天",
            "仅在用户主动导出时生成；应用不会自动上传此文件",
            "不读取 Android UsageStats 的其他应用前台时长或使用历史",
            "不包含联系人、短信、照片、麦克风内容或网络载荷",
            "不包含设备序列号、Android ID、账号令牌或应用私有文件内容",
        )))
    }.toString(2)

    fun importConfiguration(json: String): List<GuardRule> {
        val root = JSONObject(json)
        require(root.optString("format") == CONFIG_FORMAT) { "这不是只读审计配置文件" }
        val array = root.getJSONArray("targets")
        require(array.length() <= 1000) { "配置中的观察目标数量超出限制" }
        return (0 until array.length()).map { index ->
            val item = array.getJSONObject(index)
            val name = item.getString("packageName")
            require(isValidPackageName(name)) { "配置包含无效包名" }
            GuardRule(
                packageName = name,
                enabled = false,
                backupMode = null,
                permissionFingerprint = item.optString("permissionFingerprint").takeUnless { it == "null" || it.isBlank() },
                lastObservedMode = item.optString("lastObservedMode").takeUnless { it == "null" || it.isBlank() },
                lastError = item.optString("lastError").takeUnless { it == "null" || it.isBlank() },
                lastChangedAt = item.optLong("lastChangedAt", 0L).takeUnless { it == 0L },
            )
        }
    }

    fun mergeImportedRules(imported: List<GuardRule>) {
        val merged = loadRules().toMutableMap()
        imported.forEach { incoming ->
            // An imported file can add or refresh an observation target, but it must never
            // discard an active rule or the only backup that can restore it.
            val existing = merged[incoming.packageName]
            merged[incoming.packageName] = if (existing?.enabled == true || existing?.backupMode != null) {
                existing
            } else {
                incoming.copy(enabled = false, backupMode = null)
            }
        }
        saveRules(merged)
    }

    fun installedShizuku(): Boolean = runCatching {
        if (Build.VERSION.SDK_INT >= 33) {
            packageManager.getPackageInfo(SHIZUKU_PACKAGE, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(SHIZUKU_PACKAGE, 0)
        }
        true
    }.getOrDefault(false)

    fun listComponents(): List<SystemComponent> {
        val signingFlag = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else 0
        val flags = PackageManager.GET_PERMISSIONS or signingFlag
        val packages = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstalledPackages(flags)
        }
        return packages.mapNotNull { info -> componentFrom(info) }.sortedWith(
            compareByDescending<SystemComponent> { it.requestsUsageStats }
                .thenByDescending { it.isSystem }
                .thenBy { it.label.lowercase(Locale.ROOT) },
        )
    }

    fun findComponent(packageName: String): SystemComponent? {
        if (!isValidPackageName(packageName)) return null
        val signingFlag = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else 0
        val flags = PackageManager.GET_PERMISSIONS or signingFlag
        val info = runCatching {
            if (Build.VERSION.SDK_INT >= 33) {
                packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(packageName, flags)
            }
        }.getOrNull() ?: return null
        return componentFrom(info)
    }

    private fun componentFrom(info: PackageInfo): SystemComponent? {
        val appInfo = info.applicationInfo ?: return null
        val packageName = info.packageName ?: return null
        val isSystem = appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
        val category = when {
            packageName.startsWith("com.miui.") || packageName.startsWith("com.xiaomi.") -> "小米系统组件"
            packageName.contains("carrier", true) || packageName.contains("operator", true) ||
                packageName.contains(".ims") || packageName.endsWith(".stk") -> "运营商/通信组件"
            isSystem -> "Android 系统组件"
            else -> "第三方组件"
        }
        val digest = runCatching {
            val signerBytes = if (Build.VERSION.SDK_INT >= 28) {
                info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
            } else {
                @Suppress("DEPRECATION")
                info.signatures?.firstOrNull()?.toByteArray()
            }
            signerBytes?.let { bytes ->
                MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02X".format(it) }
            }.orEmpty()
        }.getOrDefault("")
        val versionCode = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else {
            @Suppress("DEPRECATION")
            info.versionCode.toLong()
        }
        return SystemComponent(
            packageName = packageName,
            label = runCatching { packageManager.getApplicationLabel(appInfo).toString() }.getOrDefault(packageName),
            uid = appInfo.uid,
            versionName = info.versionName ?: "未知版本",
            versionCode = versionCode,
            category = category,
            isSystem = isSystem,
            permissions = info.requestedPermissions.orEmpty().toSet(),
            signatureSha256 = digest,
        )
    }

    fun readUsageStatsMode(packageName: String): String {
        validateTarget(packageName)
        val result = runAppOps("get", packageName, USAGE_OP)
        check(result.exitCode == 0) { result.output.ifBlank { "AppOps 读取失败（${result.exitCode}）" } }
        return parseUsageStatsMode(result.output)
            ?: error("系统未返回可识别的 $USAGE_OP 状态；该组件或系统版本暂不可读取")
    }

    fun supportsUsageStats(packageName: String): Boolean = runCatching {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return@runCatching false
        val component = findComponent(packageName) ?: return@runCatching false
        component.requestsUsageStats
    }.getOrDefault(false)

    private fun validateTarget(packageName: String) {
        require(isValidPackageName(packageName)) { "包名格式无效" }
        check(Shizuku.pingBinder()) { "Shizuku 服务未连接" }
        check(Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) { "Shizuku 尚未授权" }
        val component = findComponent(packageName) ?: error("组件已卸载或当前用户不可见")
        check(component.requestsUsageStats) { "该组件未声明 PACKAGE_USAGE_STATS，当前无法读取此项状态" }
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) { "当前 Android 版本不支持此项只读审计" }
    }

    private fun runAppOps(vararg args: String): CommandResult {
        validateReadOnlyAppOpsArguments(args.toList())
        val binder = Shizuku.getBinder() ?: error("Shizuku Binder 不可用")
        val service = IShizukuService.Stub.asInterface(binder) ?: error("无法连接 Shizuku 服务")
        val process = service.newProcess(arrayOf(APP_OPS_PATH, *args), null, null)
        val executor = Executors.newFixedThreadPool(2)
        val outputFuture = executor.submit<String> { readRemoteStream(process.getInputStream()) }
        val errorFuture = executor.submit<String> { readRemoteStream(process.getErrorStream()) }
        try {
            val finished = process.waitForTimeout(15_000L, TimeUnit.MILLISECONDS.toString())
            if (!finished) {
                process.destroy()
                error("AppOps 命令超时")
            }
            val output = outputFuture.get(2, TimeUnit.SECONDS)
            val errorOutput = errorFuture.get(2, TimeUnit.SECONDS)
            val exitCode = runCatching { process.exitValue() }.getOrElse { -1 }
            return CommandResult(exitCode, listOf(output, errorOutput).filter { it.isNotBlank() }.joinToString("\n").trim())
        } finally {
            executor.shutdownNow()
        }
    }

    private fun readRemoteStream(descriptor: ParcelFileDescriptor?): String {
        if (descriptor == null) return ""
        return ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().use { it.readText() }
    }

    companion object {
        const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
        const val USAGE_OP = "GET_USAGE_STATS"
        private const val CONFIG_FORMAT = "hyperos-privacy-guard-readonly"
        private const val DIAGNOSTICS_FORMAT = "hyperos-privacy-guard-diagnostics"
        private val PACKAGE_REDACTION_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*){1,}")
        private const val APP_OPS_PATH = "/system/bin/appops"
        private val MODE_PATTERN = Regex("(?im)^\\s*(?:Uid mode:\\s*)?GET_USAGE_STATS\\s*:\\s*(allow|ignore|default|deny|foreground|errored)\\b")
        private val PACKAGE_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")

        fun isValidPackageName(value: String): Boolean = value.length <= 255 && PACKAGE_PATTERN.matches(value)

        internal fun parseUsageStatsMode(output: String): String? = MODE_PATTERN.find(output)
            ?.groupValues?.get(1)?.lowercase(Locale.ROOT)

        internal fun validateReadOnlyAppOpsArguments(args: List<String>) {
            require(args.firstOrNull() == "get") { "仅允许只读 AppOps 查询" }
            require(args.size == 3) { "AppOps 参数数量无效" }
            require(isValidPackageName(args[1])) { "包名格式无效" }
            require(args[2] == USAGE_OP) { "仅允许查询 GET_USAGE_STATS" }
        }
    }

    private data class CommandResult(val exitCode: Int, val output: String)
}
