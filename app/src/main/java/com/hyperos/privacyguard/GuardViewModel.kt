package com.hyperos.privacyguard

import android.app.Application
import android.content.pm.PackageManager
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku

/** Coordinates local, read-only package and AppOps observations. */
class GuardViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = GuardRepository(application)
    private val _state = MutableStateFlow(
        GuardState(
            rules = repository.loadRules(),
            logs = repository.loadLogs(),
            theme = repository.theme(),
        ),
    )
    val state: StateFlow<GuardState> = _state.asStateFlow()
    private var scanJob: Job? = null

    private val binderReceivedListener = Shizuku.OnBinderReceivedListener { refreshShizuku() }
    private val binderDeadListener = Shizuku.OnBinderDeadListener { refreshShizuku() }
    private val permissionResultListener = Shizuku.OnRequestPermissionResultListener { requestCode, result ->
        if (requestCode == SHIZUKU_PERMISSION_REQUEST) {
            refreshShizuku()
            showMessage(if (result == PackageManager.PERMISSION_GRANTED) "Shizuku 已授权" else "Shizuku 授权未通过")
        }
    }

    init {
        repository.recordUsage("app_launch")
        repository.recordUsage("page_home")
        Shizuku.addBinderReceivedListenerSticky(binderReceivedListener)
        Shizuku.addBinderDeadListener(binderDeadListener)
        Shizuku.addRequestPermissionResultListener(permissionResultListener)
        refreshShizuku()
        scanComponents()
    }

    override fun onCleared() {
        Shizuku.removeBinderReceivedListener(binderReceivedListener)
        Shizuku.removeBinderDeadListener(binderDeadListener)
        Shizuku.removeRequestPermissionResultListener(permissionResultListener)
        super.onCleared()
    }

    fun refreshShizuku() {
        val installed = repository.installedShizuku()
        val alive = runCatching { Shizuku.pingBinder() }.getOrDefault(false)
        val authorized = alive && runCatching {
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)
        _state.value = _state.value.copy(installedShizuku = installed, binderAlive = alive, authorized = authorized)
    }

    fun requestShizukuPermission() {
        repository.recordUsage("request_shizuku")
        refreshShizuku()
        val current = _state.value
        when {
            !current.installedShizuku -> showMessage("未检测到 Shizuku，请先安装并启动 Shizuku")
            !current.binderAlive -> showMessage("Shizuku 服务未运行，请启动服务后重试")
            current.authorized -> showMessage("Shizuku 已授权；本应用只执行只读查询")
            else -> runCatching { Shizuku.requestPermission(SHIZUKU_PERMISSION_REQUEST) }
                .onFailure { showMessage("无法发起 Shizuku 授权：${it.message ?: "请在 Shizuku 应用中手动授权"}") }
        }
    }

    fun scanComponents() {
        repository.recordUsage("scan_components")
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            _state.value = _state.value.copy(scanning = true, message = null)
            val result = withContext(Dispatchers.IO) { repository.listComponents() }
            _state.value = _state.value.copy(
                components = result,
                scanning = false,
                lastCheckAt = System.currentTimeMillis(),
            )
            refreshPermissionSnapshots(result)
            if (_state.value.authorized) refreshObservedModes()
        }
    }

    fun setFilter(value: String) { _state.value = _state.value.copy(filter = value) }
    fun setCategory(value: String) { _state.value = _state.value.copy(selectedCategory = value) }

    fun addManualTarget(packageName: String) {
        repository.recordUsage("add_target")
        if (!GuardRepository.isValidPackageName(packageName)) {
            showMessage("包名格式无效")
            return
        }
        viewModelScope.launch {
            val component = withContext(Dispatchers.IO) { repository.findComponent(packageName) }
            if (component == null) {
                showMessage("当前设备未找到这个组件")
            } else {
                val components = (_state.value.components.filterNot { it.packageName == packageName } + component)
                    .sortedBy { it.label.lowercase(Locale.ROOT) }
                val rules = _state.value.rules + (packageName to (_state.value.rules[packageName] ?: GuardRule(packageName)))
                repository.saveRules(rules)
                _state.value = _state.value.copy(components = components, rules = rules)
                addLog("添加观察目标", "$packageName · ${component.category}；未修改系统设置", true)
                showMessage("已添加观察目标；添加本身未修改系统设置")
            }
        }
    }

    fun auditUsageCandidates() {
        repository.recordUsage("audit_appops")
        viewModelScope.launch {
            refreshShizuku()
            if (!_state.value.authorized) {
                showMessage("活动记录 AppOps 审计需要已授权的 Shizuku")
                return@launch
            }
            auditUsageCandidatesInternal()
        }
    }

    private suspend fun auditUsageCandidatesInternal() {
        _state.value = _state.value.copy(isBusy = true, message = null)
        val candidates = _state.value.components.filter { it.requestsUsageStats }
        val modes = _state.value.observedModes.toMutableMap()
        val observations = _state.value.rules.toMutableMap()
        var failures = 0
        candidates.forEach { component ->
            val result = withContext(Dispatchers.IO) {
                runCatching { repository.readUsageStatsMode(component.packageName) }
            }
            result.onSuccess { mode ->
                modes[component.packageName] = mode
                val prior = observations[component.packageName] ?: GuardRule(component.packageName)
                val permissionChanged = prior.permissionFingerprint != null &&
                    prior.permissionFingerprint != component.permissionFingerprint
                observations[component.packageName] = prior.copy(
                    enabled = false,
                    permissionFingerprint = component.permissionFingerprint,
                    lastObservedMode = mode,
                    lastError = if (permissionChanged || prior.lastError?.contains("组件权限声明已变化") == true) {
                        "组件权限声明已变化"
                    } else {
                        null
                    },
                )
            }.onFailure { error ->
                failures++
                val prior = observations[component.packageName] ?: GuardRule(component.packageName)
                observations[component.packageName] = prior.copy(
                    enabled = false,
                    lastError = error.message ?: "读取失败",
                )
            }
        }
        val persisted = repository.saveRules(observations)
        _state.value = _state.value.copy(
            observedModes = modes,
            rules = observations,
            isBusy = false,
            lastCheckAt = System.currentTimeMillis(),
        )
        val detail = "读取 ${candidates.size} 个声明相关权限的组件；成功 ${candidates.size - failures}，失败 $failures；结果表示 AppOps 状态，不表示实际读取行为"
        addLog("活动记录能力审计", if (persisted) detail else "$detail；观察结果保存失败", persisted && failures == 0)
        if (failures > 0) showMessage("已完成只读审计：$failures 个组件无法读取")
    }

    fun checkNow() {
        repository.recordUsage("check_now")
        viewModelScope.launch {
            refreshShizuku()
            if (!_state.value.authorized) {
                _state.value = _state.value.copy(lastCheckAt = System.currentTimeMillis())
                showMessage("当前为本地只读检查：Shizuku 未授权")
                return@launch
            }
            auditUsageCandidatesInternal()
            refreshObservedModes()
            addLog("完成状态检查", "已重新读取声明 PACKAGE_USAGE_STATS 的组件状态；未修改系统设置", true)
        }
    }

    fun importRules(json: String) {
        repository.recordUsage("import_config")
        runCatching {
            val imported = repository.importConfiguration(json)
            repository.mergeImportedRules(imported)
            _state.value = _state.value.copy(rules = repository.loadRules())
            addLog("导入配置", "导入 ${imported.size} 个包名观察目标；不包含系统写入规则", true)
        }.onFailure { showMessage("导入失败：${it.message ?: "文件格式不正确"}") }
    }

    fun exportRules(): String {
        repository.recordUsage("export_config")
        return repository.exportConfiguration()
    }

    fun exportDiagnostics(): String {
        repository.recordUsage("export_diagnostics")
        return repository.exportDiagnostics(_state.value)
    }

    fun recordUsage(event: String) {
        repository.recordUsage(event)
    }

    fun clearUsageMetrics() {
        repository.clearUsageMetrics()
        showMessage("本地应用使用统计已清除")
    }

    fun setTheme(theme: String) {
        repository.recordUsage("change_theme")
        repository.setTheme(theme)
        _state.value = _state.value.copy(theme = theme)
    }

    fun consumeMessage() { _state.value = _state.value.copy(message = null) }

    private suspend fun refreshObservedModes() {
        val targets = _state.value.rules.values.filter { it.lastObservedMode != null }
        if (targets.isEmpty()) return
        val modes = _state.value.observedModes.toMutableMap()
        val observations = _state.value.rules.toMutableMap()
        var failures = 0
        targets.forEach { target ->
            val component = _state.value.components.firstOrNull { it.packageName == target.packageName }
            val permissionChanged = component != null && target.permissionFingerprint != null &&
                target.permissionFingerprint != component.permissionFingerprint
            val mode = withContext(Dispatchers.IO) {
                runCatching { repository.readUsageStatsMode(target.packageName) }
            }.getOrNull()
            if (mode != null) {
                modes[target.packageName] = mode
                observations[target.packageName] = target.copy(
                    enabled = false,
                    permissionFingerprint = component?.permissionFingerprint ?: target.permissionFingerprint,
                    lastObservedMode = mode,
                    lastError = if (permissionChanged || target.lastError?.contains("组件权限声明已变化") == true) {
                        "组件权限声明已变化"
                    } else {
                        null
                    },
                )
            } else {
                failures++
                modes.remove(target.packageName)
                observations[target.packageName] = target.copy(
                    enabled = false,
                    permissionFingerprint = component?.permissionFingerprint ?: target.permissionFingerprint,
                    lastError = buildList {
                        if (permissionChanged || target.lastError?.contains("组件权限声明已变化") == true) add("组件权限声明已变化")
                        add("无法重新读取当前 AppOps 状态")
                    }.joinToString("；"),
                )
            }
        }
        repository.saveRules(observations)
        _state.value = _state.value.copy(observedModes = modes, rules = observations)
        if (failures > 0) showMessage("有 $failures 个已记录目标暂时无法读取")
    }

    private fun refreshPermissionSnapshots(components: List<SystemComponent>) {
        val observations = _state.value.rules.toMutableMap()
        var changed = false
        components.forEach { component ->
            val prior = observations[component.packageName] ?: return@forEach
            if (prior.permissionFingerprint == null) {
                observations[component.packageName] = prior.copy(permissionFingerprint = component.permissionFingerprint)
                changed = true
            } else if (prior.permissionFingerprint != component.permissionFingerprint &&
                prior.lastError?.contains("组件权限声明已变化") != true
            ) {
                observations[component.packageName] = prior.copy(lastError = "组件权限声明已变化")
                changed = true
            }
        }
        if (changed) {
            repository.saveRules(observations)
            _state.value = _state.value.copy(rules = observations)
        }
    }

    private fun addLog(title: String, detail: String, success: Boolean) {
        val log = OperationLog(System.currentTimeMillis(), title, detail, success)
        repository.appendLog(log)
        _state.value = _state.value.copy(logs = listOf(log) + _state.value.logs.take(499))
    }

    private fun showMessage(value: String) { _state.value = _state.value.copy(message = value) }

    fun formattedLastCheck(): String = _state.value.lastCheckAt?.let {
        SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault()).format(Date(it))
    } ?: "尚未检查"

    companion object {
        private const val SHIZUKU_PERMISSION_REQUEST = 1001
    }
}
