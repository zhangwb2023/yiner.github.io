<h2 align = "center">Ubuntu22.04 安装OpenVPN</h1> 




[TOC]

### 操作系统版本

```bash
root@openvpn:~# lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.2 LTS
Release:        22.04
Codename:       jammy
```

### OpenVPN版本

```bash
root@openvpn:~# openvpn --version
OpenVPN 2.5.5 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Jul 14 2022
library versions: OpenSSL 3.0.2 15 Mar 2022, LZO 2.10
Originally developed by James Yonan
Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
Compile time defines: enable_async_push=no enable_comp_stub=no enable_crypto_ofb_cfb=yes enable_debug=yes enable_def_auth=yes enable_dependency_tracking=no enable_dlopen=unknown enable_dlopen_self=unknown enable_dlopen_self_static=unknown enable_fast_install=needless enable_fragment=yes enable_iproute2=no enable_libtool_lock=yes enable_lz4=yes enable_lzo=yes enable_maintainer_mode=no enable_management=yes enable_multihome=yes enable_option_checking=no enable_pam_dlopen=no enable_pedantic=no enable_pf=yes enable_pkcs11=yes enable_plugin_auth_pam=yes enable_plugin_down_root=yes enable_plugins=yes enable_port_share=yes enable_selinux=no enable_shared=yes enable_shared_with_static_runtimes=no enable_silent_rules=no enable_small=no enable_static=yes enable_strict=no enable_strict_options=no enable_systemd=yes enable_werror=no enable_win32_dll=yes enable_x509_alt_username=yes with_aix_soname=aix with_crypto_library=openssl with_gnu_ld=yes with_mem_check=no with_sysroot=no
```

### 安装OpenVPN和easy-rsa

**`apt-get -y install openvpn`**

**`apt-get -y install easy-rsa`**

### 配置证书生成文件

```bash
cd  /usr/share/easy-rsa/
root@openvpn:/usr/share/easy-rsa#cp vars.example  vars
root@openvpn:/usr/share/easy-rsa# cat vars | egrep -Ev '^$|#'
if [ -z "$EASYRSA_CALLER" ]; then
        echo "You appear to be sourcing an Easy-RSA 'vars' file." >&2
        echo "This is no longer necessary and is disallowed. See the section called" >&2
        echo "'How to use this file' near the top comments for more details." >&2
        return 1
fi
set_var EASYRSA_REQ_COUNTRY     "CN"
set_var EASYRSA_REQ_PROVINCE    "Shanghai"
set_var EASYRSA_REQ_CITY        "Shanghai"
set_var EASYRSA_REQ_ORG 				"yiner"
set_var EASYRSA_REQ_EMAIL       "zhangwb@yiner.net.cn"
set_var EASYRSA_REQ_OU          "yiner"
set_var EASYRSA_KEY_SIZE        2048
set_var EASYRSA_ALGO            rsa
set_var EASYRSA_CA_EXPIRE       36500
set_var EASYRSA_CERT_EXPIRE     36500
```

### 生成证书

- #### 制作CA证书

```bash
root@openvpn:/usr/share/easy-rsa# ./easyrsa  init-pki
Note: using Easy-RSA configuration from: /usr/share/easy-rsa/vars
init-pki complete; you may now create a CA or requests.
Your newly created PKI dir is: /usr/share/easy-rsa/pki
```

- #### 制作PEM文件

```bash
root@openvpn:/usr/share/easy-rsa# ./easyrsa  build-ca

Note: using Easy-RSA configuration from: /usr/share/easy-rsa/vars
Using SSL: openssl OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)

Enter New CA Key Passphrase: 设置一个CA证书密码
Re-Enter New CA Key Passphrase: 设置一个CA证书密码
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Common Name (eg: your user, host, or server name) [Easy-RSA CA]:openvpn

CA creation complete and you may now import and sign cert requests.
Your new CA certificate file for publishing is at:
/usr/share/easy-rsa/pki/ca.crt
```

- #### 制作Server证书

```bash
  root@openvpn:/usr/share/easy-rsa# ./easyrsa build-server-full server nopass
  
  Note: using Easy-RSA configuration from: /usr/share/easy-rsa/vars
  Using SSL: openssl OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)
  ......+...+.........+.....+...+.+.....+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*..+.....+.+......+...............+..+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*............+........+...+.+...........+.+...+....+.........+..............+.+.....+.........+.......+......+...+...........+.+.....+.........+......+...+....+.....+.+.....+......+.........+.......+..+......+.........+.......+...+..
  Using configuration from /usr/share/easy-rsa/pki/easy-rsa-4879.hgqFtS/tmp.sMJ3kQ
  Enter pass phrase for /usr/share/easy-rsa/pki/private/ca.key:输入CA证书密码
  80BBF1B6D57F0000:error:0700006C:configuration file routines:NCONF_get_string:no value:../crypto/conf/conf_lib.c:315:group=<NULL> name=unique_subject
  Check that the request matches the signature
  Signature ok
  The Subject's Distinguished Name is as follows
  commonName            :ASN.1 12:'server'
  Certificate is to be certified until May 28 08:04:23 2123 GMT (36500 days)
  
  Write out database with 1 new entries
  Data Base Updated
```

- #### 制作DH文件

```bash
root@openvpn:/usr/share/easy-rsa# ./easyrsa gen-dh

Note: using Easy-RSA configuration from: /usr/share/easy-rsa/vars
Using SSL: openssl OpenSSL 3.0.2 15 Mar 2022 (Library: OpenSSL 3.0.2 15 Mar 2022)
Generating DH parameters, 2048 bit long safe prime
........+.............................................................+........................................................+..........................................................................+..............+...............+.......................................+.+...........................................................................................................................................................................................................................................................................................................................++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*++*

DH parameters of size 2048 created at /usr/share/easy-rsa/pki/dh.pem
```

### 制作Client证书

```bash
root@openvpn:/usr/share/easy-rsa# ./easyrsa build-client-full  client nopass

Enter pass phrase for /usr/share/easy-rsa/pki/private/ca.key:输入CA密码
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
commonName            :ASN.1 12:'client'
Certificate is to be certified until May 28 08:32:42 2123 GMT (36500 days)

Write out database with 1 new entries
Data Base Updated
```

### 移动证书文件至OpenVPN目录

```bash
root@openvpn:/usr/share/easy-rsa# cp -a pki/ca.crt /etc/openvpn/
root@openvpn:/usr/share/easy-rsa# cp -a pki/private/server.key /etc/openvpn/
root@openvpn:/usr/share/easy-rsa# cp -a pki/issued/server.crt /etc/openvpn/
root@openvpn:/usr/share/easy-rsa# cp -a pki/dh.pem /etc/openvpn/
root@openvpn:/usr/share/easy-rsa# cp -a ta.key /etc/openvpn/
```

### 制作OpenVPN配置文件

```bash
root@openvpn:/usr/share/doc/openvpn/examples/sample-config-files# pwd
/usr/share/doc/openvpn/examples/sample-config-files
root@openvpn:/usr/share/doc/openvpn/examples/sample-config-files# cp server.conf  /etc/openvpn/
oot@openvpn:/etc/openvpn# cat server.conf  | egrep -Ev '^$|^#|^;'
local 0.0.0.0
port 1194
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt
push "route 192.168.1.0 255.255.255.0"
client-to-client
duplicate-cn
keepalive 10 120
#tls-auth ta.key 0 
data-ciphers AES-256-GCM
#compress lz4-v2
#push "compress lz4-v2"
#comp-lzo
max-clients 100
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
verb 3
```

### 开启内核转发

```bash
echo 'net.ipv4.ip_forward = 1' >>/etc/sysctl.conf
sysctl -p
```

### 启动OpenVPN服务

```bash
systemctl enable openvpn@server
systemctl start openvpn@server
```

### 配置IPTABLES

```bash
##添加规则
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens33  -j MASQUERADE
iptables -I FORWARD -i tun0 -o ens33 -s 10.8.0.0/24 -m conntrack --ctstate NEW -j ACCEPT
iptables -I FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

##查看规则
iptables -L -n -t nat


```

### 关闭Ubuntu防火墙

```bash
ufw status
ufw disable
```

### 制作OpenVPN Client配置文件

```bash
root@openvpn:/usr/share/easy-rsa# touch client.ovpn
```

```
client
dev tun
proto tcp
remote  117.143.59.110 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
data-ciphers AES-256-GCM
auth-nocache
verb 3
```

### 下载OpenVPN客户端

> https://tunnelblick.net/downloads.html

