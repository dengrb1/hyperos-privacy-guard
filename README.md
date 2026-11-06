# HyperOS Privacy Guard

HyperOS Privacy Guard 是一个 Kotlin + Jetpack Compose 的本地 Android 应用，面向 Android 14/15 及 Redmi K80 Ultra 国行 HyperOS。它通过用户授权的 Shizuku 读取设备上的组件、权限声明和 `GET_USAGE_STATS` AppOps 状态，生成可复核的本地观察记录。

应用严格保持只读：不会设置 AppOps，不会修改权限、系统配置、日志、缓存或用户数据，也不会卸载、冻结、禁用组件或联网上传设备信息。Shizuku 只用于执行固定路径的 `appops get` 查询；没有 Shizuku 时，仍可枚举本地可见的组件信息。

## 已实现

- 检测 Shizuku 是否安装、服务是否运行和授权状态。
- 枚举已安装组件，显示包名、UID、版本、权限声明和签名 SHA-256，并区分小米、运营商、Android 系统和第三方组件。
- 识别活动记录、设备标识、位置、通话、短信、麦克风、相机、悬浮窗、辅助功能等权限能力线索。
- 读取声明 `PACKAGE_USAGE_STATS` 的组件的 `GET_USAGE_STATS` AppOps 当前模式；解析失败或权限不足时标记为未观测。
- 保存权限声明指纹、最近观察模式、错误信息和本地操作日志，支持重复检查和配置导入导出。
- 支持深色/浅色/跟随系统主题，所有观察数据仅保存在应用私有存储。
- 在设置中主动导出诊断信息 JSON，包含版本、ROM/Android 环境、组件包名与权限线索、AppOps 观察结果、最近本地操作日志，以及页面/功能每日使用次数（本地保留 30 天），便于维护和问题排查；应用不会自动上传。
- Python ADB 审计器采集构建信息、包清单、权限、AppOps、后台服务/任务、UID 流量和 IPv4/IPv6 端点，并保存原始证据。

## 参考项目边界

用户提供的 [yooma1/qufz](https://github.com/yooma1/qufz) 是针对 ColorOS/OPPO 手机管家的 LSPosed 模块，依赖 root、LSPosed 和特定版本的反向工程类名。它的“分层证据、作用域限制、自测脚本和明确版本边界”可作为审计设计参考，但其 hook 代码、ColorOS 包名和云端拦截逻辑不适用于无 Root 的 HyperOS AppOps 审计。

## 安全边界

- 权限声明只说明组件申请过某项能力，不证明运行时授权或实际读取。
- AppOps 模式只表示系统策略状态，不证明组件已经读取活动记录。
- UID 流量和连接端点只证明采集时点存在网络活动，不能证明上传内容或目的。
- 应用不执行任意 Shell；ADB 审计器的设备命令来自固定只读白名单，并以 `shell=False` 调用 `adb.exe`。
- 数据不会上传第三方；原始命令输出保存在本地 `audit_output/evidence/`。
- 本地使用统计只记录本应用的页面访问与功能操作次数，不读取 Android UsageStats 中其他应用的使用历史。诊断信息导出不包含联系人、短信、照片、麦克风内容、网络载荷、设备序列号或账号令牌；分享前仍应由用户自行检查文件。

## 构建与验证

使用 Android Studio 打开项目，或执行：

```powershell
.\gradlew.bat assembleDebug
.\gradlew.bat test
python -m py_compile .\hyperos_audit.py
python -m unittest discover -s tests -v
python .\hyperos_audit.py --output-dir .\audit_output
```

APK 输出为 `app/build/outputs/apk/debug/app-debug.apk`。环境和 Shizuku 使用步骤见 [BUILD.md](BUILD.md)。

## 真机限制

当前工作区没有连接 Redmi K80 Ultra 国行 HyperOS，因此尚未完成 Shizuku 授权、不同 ROM 的 AppOps 输出、重启后状态变化和系统更新兼容性验证。无设备时脚本会生成“未观测”报告；连接并授权后重新运行即可填充实际证据。
