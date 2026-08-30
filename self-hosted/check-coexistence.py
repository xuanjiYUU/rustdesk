#!/usr/bin/env python3
"""Fail CI if a desktop packaging identity can overwrite official RustDesk."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


REQUIRED = {
    "libs/hbb_common/src/config.rs": [
        'RwLock::new("GanweiRemoteDesk".to_owned())',
        'RwLock::new("com.ganweitech".to_owned())',
    ],
    "flutter/linux/CMakeLists.txt": [
        'set(BINARY_NAME "ganwei-remotedesk")',
        'set(APPLICATION_ID "com.ganweitech.remotedesk")',
    ],
    "res/rustdesk.service": [
        "ExecStart=/usr/bin/ganwei-remotedesk --service",
        'ExecStop=pkill -f "ganwei-remotedesk --"',
    ],
    "res/rustdesk.desktop": [
        "Exec=ganwei-remotedesk %u",
        "StartupWMClass=ganwei-remotedesk",
    ],
    "res/rustdesk-link.desktop": [
        "MimeType=x-scheme-handler/ganweiremotedesk;",
        "TryExec=ganwei-remotedesk",
    ],
    "res/DEBIAN/postinst": [
        "/usr/bin/ganwei-remotedesk",
        "systemctl enable ganwei-remotedesk",
    ],
    "res/DEBIAN/prerm": [
        "systemctl stop ganwei-remotedesk",
        "rm -f /usr/bin/ganwei-remotedesk",
    ],
    "flutter/windows/CMakeLists.txt": [
        'set(BINARY_NAME "GanweiRemoteDesk")',
    ],
    "flutter/windows/runner/Runner.rc": [
        'VALUE "InternalName", "GanweiRemoteDesk"',
        'VALUE "OriginalFilename", "GanweiRemoteDesk.exe"',
    ],
    "flutter/macos/Runner/Configs/AppInfo.xcconfig": [
        "PRODUCT_NAME = GanweiRemoteDesk",
        "PRODUCT_BUNDLE_IDENTIFIER = com.ganweitech.remotedesk",
    ],
    "flutter/macos/Runner/Info.plist": [
        "<string>com.ganweitech.remotedesk</string>",
        "<string>ganweiremotedesk</string>",
    ],
    "src/server/dbus.rs": [
        'const DBUS_NAME: &str = "com.ganweitech.remotedesk";',
    ],
    "src/common.rs": [
        "keys::OPTION_ENABLE_CHECK_UPDATE.to_owned()",
        "keys::OPTION_ALLOW_AUTO_UPDATE.to_owned()",
    ],
    "src/updater.rs": [
        "Private client detected, skipping the official RustDesk update channel.",
    ],
    ".github/workflows/flutter-build.yml": [
        "--app-name GanweiRemoteDesk",
        "GanweiRemoteDesk.app",
        "ganwei-remotedesk-${{ env.VERSION }}-${{ matrix.job.arch }}.deb",
        "ganwei-remotedesk-installers-windows-${{ matrix.job.arch }}",
    ],
}


FORBIDDEN = {
    "flutter/linux/CMakeLists.txt": [
        'set(BINARY_NAME "rustdesk")',
        'set(APPLICATION_ID "com.carriez.flutter_hbb")',
    ],
    "res/rustdesk.service": ["/usr/bin/rustdesk --service"],
    "res/DEBIAN/postinst": [
        "/usr/bin/rustdesk",
        "systemctl enable rustdesk",
        "systemctl start rustdesk",
    ],
    "res/DEBIAN/prerm": [
        "systemctl stop rustdesk",
        "systemctl disable rustdesk",
    ],
    "flutter/windows/CMakeLists.txt": ['set(BINARY_NAME "rustdesk")'],
    "flutter/macos/Runner/Configs/AppInfo.xcconfig": [
        "PRODUCT_NAME = RustDesk",
        "PRODUCT_BUNDLE_IDENTIFIER = com.carriez.flutterHbb",
    ],
    "flutter/macos/Runner/Info.plist": [
        "<string>com.carriez.rustdesk</string>",
        "<string>rustdesk</string>",
    ],
    "src/server/dbus.rs": ['const DBUS_NAME: &str = "org.rustdesk.rustdesk";'],
}


def main() -> int:
    errors = []
    cache = {}

    for relative, needles in REQUIRED.items():
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"missing file: {relative}")
            continue
        body = cache.setdefault(relative, path.read_text(encoding="utf-8"))
        for needle in needles:
            if needle not in body:
                errors.append(f"{relative}: missing required identity: {needle}")

    for relative, needles in FORBIDDEN.items():
        path = ROOT / relative
        if not path.is_file():
            continue
        body = cache.setdefault(relative, path.read_text(encoding="utf-8"))
        for needle in needles:
            if needle in body:
                errors.append(f"{relative}: official identity still owns a private resource: {needle}")

    if errors:
        print("Desktop coexistence check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print("Desktop coexistence identities are isolated for macOS, Ubuntu and Windows.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
