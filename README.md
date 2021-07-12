# log_pwn

感谢franki大佬！！！

最初目的是用于pwn的流量审计

## 远程流量审计

在服务端通过upload.py可以将pcap文件分析后上传至redis，然后本地通过query.py查询会话

## 本地流量分析

通过analyse.py分析pcap包，查接出文件内所有的会话。 