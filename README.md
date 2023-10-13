# FridaAndroidMemoryScan
使用frida在Android内存中扫描目标内容

Usage:
    1.Modify the value of the pattern variable as the search target
    2.frida -U -f [packageName] -l frida_android_memory_scan.js --no-pause
