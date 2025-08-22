# Lite Mihomo Proxy
本项目一个仅支持windows的[mihomo](https://github.com/MetaCubeX/mihomo)启动器

---
注意事项：

- LMP.exe带黑窗日志，LMP-tray.exe只有托盘图标
- 将mihomo核心下载到LMP*.exe程序相同目录，重命名为```serv.exe```
- 托盘图标支持两种模式，系统代理和Tun
- 通过注册表来添加win的系统代理
- 确保可以通过命令```.\serv.exe -d . -f .\config.yaml```启动核心
- 确保你的config.yaml配置文件可用

