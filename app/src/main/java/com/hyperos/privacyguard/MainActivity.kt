package com.hyperos.privacyguard

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.Error
import androidx.compose.material.icons.outlined.FactCheck
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Upload
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {
    private val viewModel by viewModels<GuardViewModel>()
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); setContent { PrivacyGuardApp(viewModel) } }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PrivacyGuardApp(viewModel: GuardViewModel) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    var page by remember { mutableStateOf(GuardPage.HOME) }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val context = androidx.compose.ui.platform.LocalContext.current
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri: Uri? ->
        uri ?: return@rememberLauncherForActivityResult
        runCatching { context.contentResolver.openOutputStream(uri)?.use { it.write(viewModel.exportRules().toByteArray()) } ?: error("无法写入目标文件") }
            .onFailure { scope.launch { snackbar.showSnackbar("导出失败：${it.message ?: "未知错误"}") } }
    }
    val diagnosticLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri: Uri? ->
        uri ?: return@rememberLauncherForActivityResult
        runCatching { context.contentResolver.openOutputStream(uri)?.use { it.write(viewModel.exportDiagnostics().toByteArray()) } ?: error("无法写入目标文件") }
            .onFailure { scope.launch { snackbar.showSnackbar("诊断信息导出失败：${it.message ?: "未知错误"}") } }
    }
    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri ?: return@rememberLauncherForActivityResult
        runCatching { context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() } ?: error("无法读取配置文件") }
            .onSuccess(viewModel::importRules).onFailure { scope.launch { snackbar.showSnackbar("导入失败：${it.message ?: "未知错误"}") } }
    }
    LaunchedEffect(state.message) { state.message?.let { snackbar.showSnackbar(it); viewModel.consumeMessage() } }
    PrivacyGuardTheme(state.theme) {
        Scaffold(
            modifier = Modifier.windowInsetsPadding(WindowInsets.safeDrawing),
            topBar = { TopAppBar(title = { Text(page.label) }, actions = { if (state.scanning || state.isBusy) CircularProgressIndicator(Modifier.size(20.dp)) else IconButton(onClick = viewModel::checkNow) { Icon(Icons.Outlined.Refresh, "检查") } }) },
            bottomBar = { NavigationBar(windowInsets = WindowInsets.navigationBars) {
                listOf(GuardPage.HOME to Icons.Outlined.Security, GuardPage.PROTECTION to Icons.Outlined.Security, GuardPage.COMPONENTS to Icons.Outlined.Apps, GuardPage.LOGS to Icons.Outlined.History, GuardPage.SETTINGS to Icons.Outlined.Settings).forEach { (target, icon) -> NavigationBarItem(selected = page == target, onClick = { if (page != target) { page = target; viewModel.recordUsage("page_${target.usageKey}") } }, icon = { Icon(icon, target.label) }, label = { Text(target.label) }) }
            } },
            snackbarHost = { SnackbarHost(snackbar) },
        ) { padding ->
            Column(Modifier.fillMaxSize().padding(padding)) {
                when (page) {
                    GuardPage.HOME -> HomeScreen(state, viewModel) { if (page != it) { page = it; viewModel.recordUsage("page_${it.usageKey}") } }
                    GuardPage.PROTECTION -> ProtectionScreen(state, viewModel)
                    GuardPage.AUDIT -> AuditScreen(state, viewModel)
                    GuardPage.COMPONENTS -> ComponentsScreen(state, viewModel)
                    GuardPage.PERMISSIONS -> PermissionsScreen(state)
                    GuardPage.LOGS -> LogsScreen(state)
                    GuardPage.RESEARCH -> ResearchScreen()
                    GuardPage.NETWORK -> NetworkScreen()
                    GuardPage.SETTINGS -> SettingsScreen(state, viewModel, exportLauncher, importLauncher, diagnosticLauncher)
                }
            }
        }
    }
}

@Composable
private fun HomeScreen(state: GuardState, viewModel: GuardViewModel, open: (GuardPage) -> Unit) {
    val restricted = state.observedModes.values.count { it == "ignore" }
    val signals = state.components.count { it.privacySignals.isNotEmpty() }
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { Card { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("HyperOS Privacy Guard", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Text(if (state.authorized) "Shizuku 已授权 · 仅执行只读 AppOps 查询" else "Shizuku 未授权 · 设备信息仍可本地查看")
            Text("最近检查：${if (state.lastCheckAt == null) "尚未检查" else viewModel.formattedLastCheck()}", style = MaterialTheme.typography.bodySmall)
            if (!state.compatibility.supported) Text(state.compatibility.reason, color = MaterialTheme.colorScheme.error)
            OutlinedButton(onClick = viewModel::requestShizukuPermission) { Text(if (state.authorized) "重新检查连接" else "连接 / 授权 Shizuku") }
        } } }
        item { Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) { MetricCard("AppOps 为 ignore", restricted.toString(), Modifier.weight(1f)); MetricCard("权限线索", signals.toString(), Modifier.weight(1f)); MetricCard("组件", state.components.size.toString(), Modifier.weight(1f)) } }
        item { Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("本地审计", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold); Text("观察权限声明与系统返回的 AppOps 状态；应用不会写入设备设置。")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { Button(onClick = { open(GuardPage.PROTECTION) }) { Icon(Icons.Outlined.Security, null); Spacer(Modifier.width(6.dp)); Text("活动记录") }; OutlinedButton(onClick = { open(GuardPage.AUDIT) }) { Icon(Icons.Outlined.FactCheck, null); Spacer(Modifier.width(6.dp)); Text("审计详情") } }
        } } }
        item { FeatureRow("权限管理", "查看设备标识、位置和活动记录能力线索") { open(GuardPage.PERMISSIONS) } }
        item { FeatureRow("数据欺骗研究", "公开接口限制与不可用能力说明") { open(GuardPage.RESEARCH) } }
        item { FeatureRow("网络审计", "当前版本不拦截或归因其他进程网络请求") { open(GuardPage.NETWORK) } }
    }
}

@Composable
private fun ProtectionScreen(state: GuardState, viewModel: GuardViewModel) {
    var filter by remember { mutableStateOf("") }
    val candidates = state.components.filter { it.requestsUsageStats && (filter.isBlank() || it.packageName.contains(filter, true) || it.label.contains(filter, true)) }
    Column(Modifier.fillMaxSize()) {
        Card(Modifier.fillMaxWidth().padding(16.dp)) { Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("活动记录 AppOps", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold); Text("只读取声明 PACKAGE_USAGE_STATS 的组件状态。AppOps 模式和权限声明都不能单独证明实际读取行为。", style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = viewModel::auditUsageCandidates, enabled = state.authorized && !state.isBusy) { Text("读取当前状态") }
        } }
        OutlinedTextField(filter, { filter = it }, Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp), singleLine = true, label = { Text("筛选包名或名称") })
        LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { items(candidates, key = { it.packageName }) { component ->
            val rule = state.rules[component.packageName]; val current = state.observedModes[component.packageName] ?: rule?.lastObservedMode
            Card(Modifier.fillMaxWidth()) { Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(component.label, fontWeight = FontWeight.SemiBold)
                Text(component.packageName, style = MaterialTheme.typography.labelSmall)
                Text("GET_USAGE_STATS：${current ?: "未观测"}", style = MaterialTheme.typography.bodySmall)
                if (rule?.lastError != null) Text(rule.lastError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                if (rule?.backupMode != null || rule?.enabled == true) {
                    Text("旧版本备份模式：${rule?.backupMode ?: "未记录"}。本版本不会用该备份修改设备；如需还原，请在系统设置中核对。", style = MaterialTheme.typography.labelSmall)
                }
            } }
        } }
    }
}

@Composable
private fun AuditScreen(state: GuardState, viewModel: GuardViewModel) {
    val candidates = state.components.filter { it.requestsUsageStats }
    Column(Modifier.fillMaxSize()) {
        Card(Modifier.fillMaxWidth().padding(16.dp)) { Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { Text("活动记录审计", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold); Text("读取 GET_USAGE_STATS AppOps 当前模式；权限声明不代表实际读取行为。"); Button(onClick = viewModel::auditUsageCandidates, enabled = state.authorized && !state.isBusy) { Text("读取当前状态") } } }
        LazyColumn(contentPadding = PaddingValues(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { items(candidates, key = { it.packageName }) { component -> val rule = state.rules[component.packageName]; Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) { Text(component.label, fontWeight = FontWeight.SemiBold); Text(component.packageName, style = MaterialTheme.typography.labelSmall); Text("GET_USAGE_STATS：${state.observedModes[component.packageName] ?: rule?.lastObservedMode ?: "未观测"}"); if (rule?.lastError != null) Text(rule.lastError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) } } } }
    }
}

@Composable
private fun ComponentsScreen(state: GuardState, viewModel: GuardViewModel) {
    var filter by remember { mutableStateOf("") }; var manualPackage by remember { mutableStateOf("") }
    val categories = listOf("全部") + state.components.map { it.category }.distinct(); val visible = state.components.filter { (state.selectedCategory == "全部" || it.category == state.selectedCategory) && (filter.isBlank() || it.packageName.contains(filter, true) || it.label.contains(filter, true)) }
    Column(Modifier.fillMaxSize()) {
        OutlinedTextField(filter, { filter = it }, Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), singleLine = true, label = { Text("筛选包名或名称") })
        Row(Modifier.padding(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) { categories.take(3).forEach { category -> FilterChip(selected = state.selectedCategory == category, onClick = { viewModel.setCategory(category) }, label = { Text(category) }) } }
        Row(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) { OutlinedTextField(manualPackage, { manualPackage = it }, Modifier.weight(1f), singleLine = true, label = { Text("手动添加包名") }); Button(onClick = { viewModel.addManualTarget(manualPackage); manualPackage = "" }, enabled = manualPackage.isNotBlank()) { Text("添加") } }
        LazyColumn(contentPadding = PaddingValues(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { items(visible, key = { it.packageName }) { component -> Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) { Text(component.label, fontWeight = FontWeight.SemiBold); Text(component.packageName, style = MaterialTheme.typography.labelSmall); Text("UID ${component.uid} · ${component.versionName} · ${component.category}", style = MaterialTheme.typography.bodySmall); Text("权限线索：${component.privacySignals.ifEmpty { listOf("未识别") }.joinToString("、")}", style = MaterialTheme.typography.bodySmall); Text("签名 SHA-256：${component.signatureSha256.ifBlank { "不可读取" }}", style = MaterialTheme.typography.labelSmall, maxLines = 1, overflow = TextOverflow.Ellipsis) } } } }
    }
}

@Composable
private fun PermissionsScreen(state: GuardState) { LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { item { Text("权限声明是能力线索，不代表运行时授权或实际读取。", style = MaterialTheme.typography.bodySmall) }; items(state.components.filter { it.privacySignals.isNotEmpty() }, key = { it.packageName }) { component -> Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(14.dp)) { Text(component.packageName, fontWeight = FontWeight.SemiBold); Text(component.privacySignals.joinToString(" · ")) } } } } }

@Composable
private fun ResearchScreen() { LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) { item { Text("数据研究边界", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold) }; item { Card { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { Text("当前状态：只读观察", fontWeight = FontWeight.SemiBold); Text("本应用通过 Shizuku 读取受控系统命令的返回值，但不 Hook 其他进程、不注入虚假 UsageStats，也不修改 AppOps。公开接口无法实现的能力会保持不可用，不显示伪造成功状态。") } } }; item { Text("可研究方向：记录目标组件声明的权限与 AppOps 状态，比较系统重启或更新后的变化；真实数据源和调用者级返回值仍需系统框架或进程级 Hook。") } } }
@Composable
private fun NetworkScreen() { EmptyState("网络审计不可用：本应用不拦截或归因其他进程的全部网络请求") }
@Composable
private fun LogsScreen(state: GuardState) { if (state.logs.isEmpty()) EmptyState("暂无本地操作记录") else LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { items(state.logs, key = { "${it.timestamp}-${it.title}" }) { log -> Card(Modifier.fillMaxWidth()) { Row(Modifier.padding(14.dp)) { Icon(if (log.success) Icons.Outlined.CheckCircle else Icons.Outlined.Error, null); Column(Modifier.padding(start = 8.dp)) { Text(log.title, fontWeight = FontWeight.SemiBold); Text(SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(log.timestamp)), style = MaterialTheme.typography.labelSmall); Text(log.detail, style = MaterialTheme.typography.bodySmall) } } } } } }

@Composable
private fun SettingsScreen(state: GuardState, viewModel: GuardViewModel, exportLauncher: androidx.activity.result.ActivityResultLauncher<String>, importLauncher: androidx.activity.result.ActivityResultLauncher<Array<String>>, diagnosticLauncher: androidx.activity.result.ActivityResultLauncher<String>) { Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) { Text("设置", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold); Text("本应用严格只读：只枚举组件、读取权限声明和读取 GET_USAGE_STATS AppOps。所有观察结果与日志仅保存在本机。"); Card { Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) { Text("兼容性", fontWeight = FontWeight.SemiBold); Text("Android ${state.compatibility.api} / ${state.compatibility.release}"); Text(state.compatibility.reason) } }; Divider(); Text("外观", fontWeight = FontWeight.SemiBold); Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { listOf("system" to "跟随系统", "light" to "浅色", "dark" to "深色").forEach { (key, label) -> FilterChip(selected = state.theme == key, onClick = { viewModel.setTheme(key) }, label = { Text(label) }) } }; Divider(); Text("配置", fontWeight = FontWeight.SemiBold); Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { OutlinedButton(onClick = { exportLauncher.launch("hyperos-privacy-guard.json") }) { Icon(Icons.Outlined.Download, null); Spacer(Modifier.width(6.dp)); Text("导出") }; OutlinedButton(onClick = { importLauncher.launch(arrayOf("application/json", "text/plain")) }) { Icon(Icons.Outlined.Upload, null); Spacer(Modifier.width(6.dp)); Text("导入") } }; Text("本地使用统计", fontWeight = FontWeight.SemiBold); Text("仅记录本应用的页面访问和功能操作次数，按日累计并保留 30 天；不读取 Android UsageStats 中其他应用的使用历史。", style = MaterialTheme.typography.bodySmall); Text("诊断信息", fontWeight = FontWeight.SemiBold); Text("手动导出会包含设备型号、组件包名与权限线索、AppOps 观察结果、最近操作日志和上述统计。应用不会上传；请检查文件后再分享。", style = MaterialTheme.typography.bodySmall); Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { OutlinedButton(onClick = { diagnosticLauncher.launch("hyperos-privacy-guard-diagnostics.json") }) { Icon(Icons.Outlined.Download, null); Spacer(Modifier.width(6.dp)); Text("导出诊断信息") }; TextButton(onClick = viewModel::clearUsageMetrics) { Icon(Icons.Outlined.Delete, null); Spacer(Modifier.width(6.dp)); Text("清除本地使用统计") } } } }

@Composable
private fun HomeMetric(label: String, value: String, modifier: Modifier) { Card(modifier) { Column(Modifier.padding(10.dp)) { Text(value, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold); Text(label, style = MaterialTheme.typography.labelSmall) } } }
@Composable
private fun MetricCard(label: String, value: String, modifier: Modifier) = HomeMetric(label, value, modifier)
@Composable
private fun FeatureRow(title: String, subtitle: String, onClick: () -> Unit) { Card(Modifier.fillMaxWidth().clickable(onClick = onClick)) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) { Text(title, fontWeight = FontWeight.SemiBold); Text(subtitle, style = MaterialTheme.typography.bodySmall) } } }
@Composable
private fun EmptyState(text: String) { Column(Modifier.fillMaxSize().padding(32.dp), verticalArrangement = Arrangement.Center) { Icon(Icons.Outlined.WarningAmber, null); Text(text) } }
