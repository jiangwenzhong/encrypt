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
package com.jwz.encrypt.unsymmetric;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

/**
 * @author chenzhaojie
 * @date 2018/10/22
 */
public class RsaUtils {

    public static String encrypt(String content, String empoent, String module) {

        try {
            // 传入的字符串需要转置，因为android内部库做了一次转置，但是SenseLink后台又做了一次转置，
            // 如果不在该处手动转置则会出错，如果该工具类需要使用在对接其他后台时需要注意根据实际情况来修改是否需要转置
            StringBuilder sb = new StringBuilder(content);
            content = sb.reverse().toString();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            BigInteger modulus = new BigInteger(module, 16);
            BigInteger publicExponent = new BigInteger(empoent, 16);
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return byteToHexString(cipher.doFinal(content.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String byteToHexString(byte[] bytes) {

        String hexStr = "0123456789ABCDEF";
        StringBuilder result = new StringBuilder();
        String hex;
        for (int i = 0; i < bytes.length; i++) {
            //字节高4位
            hex = String.valueOf(hexStr.charAt((bytes[i] & 0xF0) >> 4));
            //字节低4位
            hex += String.valueOf(hexStr.charAt(bytes[i] & 0x0F));
            result.append(hex);
        }
        return result.toString();
    }
}
