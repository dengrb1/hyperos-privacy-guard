# HyperOS Security Audit

## 目标

在 Windows 10/11 上通过 Android 官方 ADB Platform Tools 对 Redmi K80 Ultra 国行版 HyperOS 做第一阶段只读隐私审计。

## 约束

- 需要 USB 调试和用户在手机端批准的 ADB 授权。
- 不需要 Root，不解锁 Bootloader。
- 不卸载、禁用、冻结或修改任何组件、权限、系统配置、日志、缓存和用户数据。
- 不向第三方上传设备信息。
- 网上曝光的组件只作为检索线索；必须以设备命令实际输出为证据。
- 权限和域名只能说明能力或连接线索，不能单独证明读取或上传内容。

## 验证命令

```powershell
python -m py_compile .\hyperos_audit.py
python .\hyperos_audit.py --output-dir .\audit_output
```

无设备时工具仍生成本地未观测报告；授权手机连接后再次运行即可。
