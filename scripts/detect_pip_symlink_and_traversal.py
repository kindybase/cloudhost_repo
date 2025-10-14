#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
detect_pip_symlink_and_traversal.py
-----------------------------------
掃描:
  1. 實體目錄中是否存在符號連結 (symlink)
  2. 壓縮檔案 (.tar, .whl, .zip, .tar.gz) 內部是否含有:
     - 相對路徑穿越 ("..")
     - 絕對路徑開頭 ("/")
     - 檔案型態為 symlink

若發現疑慮，會:
  - 印出報告
  - 建立一個 SCAN_FAILED 檔案於掃描根目錄中
"""
import os
import sys
import stat
import tarfile
import zipfile
from pathlib import Path

def report_symlinks(root, found_issues):
    print(f"🔍 掃描目錄 symlink: {root}")
    for p in Path(root).rglob('*'):
        try:
            if p.is_symlink():
                target = os.readlink(p)
                print(f"⚠️ SYMLINK: {p} -> {target}")
                found_issues.append(f"SYMLINK:{p}->{target}")
        except Exception as e:
            print(f"[錯誤] {p}: {e}")

def check_tar_for_traversal(tar_path):
    issues = []
    try:
        with tarfile.open(tar_path, "r:*") as t:
            for m in t.getmembers():
                name = m.name
                if name.startswith("/") or ".." in Path(name).parts:
                    issues.append(("path-traversal", name))
                if m.issym() or m.islnk():
                    issues.append(("archive-symlink", name))
    except Exception as e:
        issues.append(("error", str(e)))
    return issues

def check_zip_for_traversal(zip_path):
    issues = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for name in z.namelist():
                if name.startswith("/") or ".." in Path(name).parts:
                    issues.append(("path-traversal", name))
                zi = z.getinfo(name)
                ext = (zi.external_attr >> 16) & 0xFFFF
                if ext & stat.S_IFLNK == stat.S_IFLNK:
                    issues.append(("archive-symlink", name))
    except Exception as e:
        issues.append(("error", str(e)))
    return issues

def scan_archives(root, found_issues):
    print(f"\n📦 掃描壓縮檔案 (tar/zip/whl) 路徑: {root}")
    for p in Path(root).rglob('*'):
        if p.is_file():
            lower = p.suffix.lower()
            if lower in ['.gz', '.tgz', '.tar', '.whl'] or p.name.endswith('.tar.gz') or p.name.endswith('.tar'):
                issues = check_tar_for_traversal(p)
            elif lower == '.zip':
                issues = check_zip_for_traversal(p)
            else:
                continue

            if issues:
                print(f"⚠️ {p} → 發現 {len(issues)} 項可疑內容:")
                for itype, name in issues:
                    print(f"   - {itype}: {name}")
                    found_issues.append(f"{itype}:{p}:{name}")

def main():
    if len(sys.argv) < 2:
        print("使用方式: python detect_pip_symlink_and_traversal.py /path/to/scan")
        sys.exit(1)
    root = sys.argv[1]
    if not os.path.exists(root):
        print("❌ 指定路徑不存在")
        sys.exit(1)

    found_issues = []
    report_symlinks(root, found_issues)
    scan_archives(root, found_issues)

    if found_issues:
        print("\n🚨 檢測發現潛在問題，請人工檢查以下項目：")
        for item in found_issues:
            print("  -", item)
        flag_path = Path(root) / "SCAN_FAILED"
        with open(flag_path, "w") as f:
            f.write("\n".join(found_issues))
        print(f"⚠️ 已建立標記檔案: {flag_path}")
        sys.exit(2)
    else:
        print("\n✅ 未發現可疑 symlink 或 path traversal。")
        sys.exit(0)

if __name__ == "__main__":
    main()

