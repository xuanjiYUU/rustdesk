# 感维科技remoteDesk 与官方 RustDesk 共存说明

本私有客户端使用独立的桌面身份，不覆盖官方 RustDesk：

| 项目 | 感维科技remoteDesk | 官方 RustDesk |
| --- | --- | --- |
| 内部应用名 | `GanweiRemoteDesk` | `RustDesk` |
| URL 协议 | `ganweiremotedesk://` | `rustdesk://` |
| macOS 应用 | `GanweiRemoteDesk.app` | `RustDesk.app` |
| macOS Bundle ID | `com.ganweitech.remotedesk` | `com.carriez.rustdesk` |
| Windows 程序/服务 | `GanweiRemoteDesk.exe` / `GanweiRemoteDesk` | `rustdesk.exe` / `RustDesk` |
| Ubuntu 包/程序/服务 | `ganwei-remotedesk` | `rustdesk` |

两个版本拥有独立配置目录、设备 ID、服务、注册表/launchd/systemd 项和协议处理器，因此可以同时安装、分别启动，也可以分别卸载。

注意：独立配置意味着首次安装私有版后需要单独登录，并重新授予 macOS 屏幕录制、辅助功能等系统权限。两个客户端可以继续连接同一套 A100 服务；共存改造不改变 `21114` 至 `21119` 的服务端口。

CI 会执行 `python3 self-hosted/check-coexistence.py`，防止后续修改意外把安装路径、服务名或协议改回官方标识。
