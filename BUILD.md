# 构建与运行

## 环境

- Android Studio（建议稳定版）
- JDK 17
- Android SDK Platform 35、Build Tools 35.0.0
- Gradle 8.13（项目包含 `gradlew.bat`）
- Windows 上的 Android 官方 Platform Tools（运行 Python 审计器时需要 `adb.exe`）

## 构建与测试

```powershell
.\gradlew.bat assembleDebug
.\gradlew.bat test
python -m py_compile .\hyperos_audit.py
python -m unittest discover -s tests -v
```

APK：`app/build/outputs/apk/debug/app-debug.apk`。

## 设备使用

1. 在 Redmi K80 Ultra 国行 HyperOS 上打开 USB 调试，并在手机端批准 ADB 授权。
2. 安装并启动 Shizuku；应用只请求读取所需的 Shizuku 授权。
3. 安装 APK，进入“系统组件”确认包名、UID、权限声明和签名信息。
4. 进入“活动记录”读取 `GET_USAGE_STATS` AppOps 当前模式；读取操作不会写入设备。
5. 需要生成完整证据目录时，在 Windows PowerShell 执行：

```powershell
python .\hyperos_audit.py --output-dir .\audit_output
```

如果连接多台设备，使用 `--serial <serial>` 指定目标。没有授权设备时，脚本仍会生成本地“未观测”报告。

如果 Shizuku 断开，受限 AppOps 查询会停止；恢复连接后可重新检查。应用和脚本都不会执行卸载、冻结、禁用、Root、系统分区写入或网络上传。

## 真机验证清单

- ADB 授权、多个设备选择和无设备报告。
- Shizuku 安装检测、服务重启、授权撤销和重新连接。
- 不同 Android/HyperOS 版本的 `appops get` 输出解析。
- 声明与未声明 `PACKAGE_USAGE_STATS` 的组件、目标卸载和权限声明变化。
- IPv4/IPv6 端点、UID 流量统计不可用时的降级行为。
- 系统重启和 HyperOS 更新后的重复采样结果。
