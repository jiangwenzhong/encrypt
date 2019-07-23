# BI-Encrypt(加密工具)

字符串，byte[]，文件等对象的加密和解密工具集合，包含了多种加密方案。

| 加密类型  | 摘要                | 相关方法            |
| ----- | ----------------- | --------------- |
| 简单加密  | 换一种编码格式           | Base64Util      |
| 单向加密  | 只能加密，不能解密         | MD5Util、SHAUtil |
| 对称加密  | 使用相同的秘钥加密和解密      | AESUtil、DESUtil、GzipUtils |
| 非对称加密 | 分公钥和私钥，一个加密，另一个解密 | RSAUtil         |
| JNI层实现 | DES、MD5 | EncryptionClient |

## 使用方法

### Base64util

| 方法                                  | 摘要   |
| ----------------------------------- | ---- |
| String  base64EncodeStr(String str) | 编码   |
| String base64DecodedStr(String str) | 解码   |


### MD5Util

| 方法                                     | 摘要         |
| -------------------------------------- | ---------- |
| String md5(String string)              | 加密字符串      |
| String md5(String string, String slat) | 加密字符串同时加盐  |
| String md5(String string, int times)   | 多次加密       |
| String md5(File file)                  | 计算文件的md5数值 |


### SHAUtil

| 方法                                     | 摘要   |
| -------------------------------------- | ---- |
| String sha(String string, String type) | 加密   |


### AESUtil

| 方法                                       | 摘要    |
| ---------------------------------------- | ----- |
| String aes(String content, String password,  int type) | 加密／解密 |


### DESUtil

| 方法                                       | 摘要    |
| ---------------------------------------- | ----- |
| String des(String content, String password,  int type) | 加密／解密 |


### RSAUtil

| 方法                                       | 摘要                             |
| ---------------------------------------- | ------------------------------ |
| Map\<String, Object\> getKeyPair()       | 随机获取密钥(公钥和私钥), 客户端公钥加密，服务器私钥解密 |
| String getKey(Map\<String, Object\> keyMap, boolean isPublicKey) | 获取公钥/私钥(true：获取公钥，false：获取私钥)  |
| String sign(byte[] data, String privateKey) | 获取数字签名                         |
| boolean verify(byte[] data, String publicKey, String sign) | 数字签名校验                         |
| byte[] rsa(byte[] data, String string,  int type) | Rsa加密/解密（一般情况下，公钥加密私钥解密）       |


### FileEncryptlUtil

| 方法                                  | 摘要   |
| ----------------------------------- | ---- |
| void init(Context context) | 初始化   |
| byte[] encryptFile(File file) | 加密文件   |
| InputStream getCipherInputStream(String file) | 解密文件   |
