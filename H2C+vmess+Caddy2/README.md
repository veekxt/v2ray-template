原理图：
v2ray client <----- H2 ------> caddy2 <-- H2C --> v2ray server

注意： 
1、目前仅 caddy2 的 v2.2.0-rc.1 版及以后完美支持 v2ray 的 H2C，实现 H2(HTTP/2) 应用。
2、另 VLESS 协议配置类似。仅修改各自 v2ray 服务器与客户端对应协议及参数即可。
