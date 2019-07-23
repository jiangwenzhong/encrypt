/**
 * Copyright 2019 蒋文忠
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.jwz.encrypt;

import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

public class EncryptionClient {

    static {
        System.loadLibrary("BIEncrypt");
    }


    public static native String randomEncryptKey();

    /**
     * 加盐后md5加密
     *
     * @param var0 待加盐加密的字符串
     * @return 加盐加密后的字符串
     */
    public static native String md5WithSalt(String var0);

    /**
     * des加密
     *
     * @param plainText 待加密字符串
     * @return 加密后的字符串
     */
    public static native String encryptByDes(String plainText);

    /**
     * des解密
     *
     * @param cipherText 待解密字符串
     * @return 解密后的字符串
     */
    public static native String decryptByDes(String cipherText) throws Exception;

    /**
     * 参数签名
     *
     * @param params 待签名的参数键值对
     * @return 参数签名后的md5值
     */
    public static String getSign(TreeMap<String, String> params) {
        StringBuffer sb = new StringBuffer();
        Iterator var3 = params.entrySet().iterator();

        while (var3.hasNext()) {
            Map.Entry sign = (Map.Entry) var3.next();
            sb.append((String) sign.getKey()).append("=").append((String) sign.getValue());
            sb.append("&");
        }

        sb.deleteCharAt(sb.length() - 1);
        String sign1 = md5WithSalt(sb.toString());
        return sign1;
    }
}
