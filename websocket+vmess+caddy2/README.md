原理图： 
v2ray client <----- websocket+tls ------> caddy2 <-- websocket --> v2ray server

注意：VLESS、 shadowsocks、socks协议配置类似。仅各自修改 v2ray 服务器与客户端对应协议及参数即可。
