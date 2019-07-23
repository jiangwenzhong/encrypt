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
#include "com_jwz_encrypt_EncryptionClient.h"
#include "md5.h"
#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <zconf.h>

const Byte key[] = "145aa7717bf9745b91e9569b80bbf1eedaa6cc6cd0e26317d810e35710f44cf8";
const char *SALT = "#145aa7717bf9745b91e9569b80bbf1eedaa6cc6cd0e26317d810e35710f44cf8";

JNIEXPORT jstring JNICALL Java_com_jwz_encrypt_EncryptionClient_md5WithSalt(
        JNIEnv *env, jclass clzz, jstring jstr) {
    const char *sourceStr = env->GetStringUTFChars(jstr, 0);
    char *sourceStrWithSalt = join(sourceStr, SALT);
    env->ReleaseStringUTFChars(jstr, sourceStr);
    unsigned char digest[16], digestHex[33];
    memset(digestHex, 0, 33);
    MD5_CTX md5;
    MD5Init(&md5);
    MD5UpdaterString(&md5, sourceStrWithSalt);
    MD5Final(digest, &md5);
    ByteToHexStr(digest, digestHex, 16);
    free(sourceStrWithSalt);
    return env->NewStringUTF((const char *) digestHex);
}


JNIEXPORT jstring JNICALL Java_com_jwz_encrypt_EncryptionClient_encryptByDes
        (JNIEnv *env, jclass clzz, jstring jstr) {
    const char *des = "DES";
    const char *desP = "DES/ECB/PKCS5Padding";
    const char *charset = "UTF-8";
    if (jstr != NULL && env->GetStringLength(jstr) > 0) {
        jclass String = env->FindClass("java/lang/String");
        jmethodID String_getBytes = env->GetMethodID(String, "getBytes",
                                                     "(Ljava/lang/String;)[B");
        // 创建一个密匙工厂
        jclass SecretKeyFactory = env->FindClass("javax/crypto/SecretKeyFactory");
        jmethodID SecretKeyFactory_getInstance = env->GetStaticMethodID(SecretKeyFactory,
                                                                        "getInstance",
                                                                        "(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;");
        jobject keyFactory = env->CallStaticObjectMethod(SecretKeyFactory,
                                                         SecretKeyFactory_getInstance,
                                                         env->NewStringUTF(des));
        // 创建一个DESKeySpec对象
        jclass DESKeySpec = env->FindClass("javax/crypto/spec/DESKeySpec");
        jmethodID DESKeySpec_init = env->GetMethodID(DESKeySpec, "<init>", "([B)V");
        jbyte *by = (jbyte *) key;
        jbyteArray keyByte = env->NewByteArray(64);
        env->SetByteArrayRegion(keyByte, 0, 64, by);
        jobject dks = env->NewObject(DESKeySpec, DESKeySpec_init, keyByte);
        // 将DESKeySpec对象转换成SecretKey对象
        jclass SecretKey = env->FindClass("javax/crypto/SecretKey");
        jmethodID SecretKeyFactory_generateSecret = env->GetMethodID(SecretKeyFactory,
                                                                     "generateSecret",
                                                                     "(Ljava/security/spec/KeySpec;)Ljavax/crypto/SecretKey;");
        jobject secretKey = env->CallObjectMethod(keyFactory, SecretKeyFactory_generateSecret,
                                                  dks);
        // 用密匙初始化Cipher对象
        jclass Cipher = env->FindClass("javax/crypto/Cipher");
        jmethodID Cipher_getInstance = env->GetStaticMethodID(Cipher,
                                                              "getInstance",
                                                              "(Ljava/lang/String;)Ljavax/crypto/Cipher;");
        jobject cipher = env->CallStaticObjectMethod(Cipher, Cipher_getInstance,
                                                     env->NewStringUTF(desP));
        // Cipher对象实际完成加密操作
        jmethodID Cipher_init = env->GetMethodID(Cipher, "init", "(ILjava/security/Key;)V");
        env->CallVoidMethod(cipher, Cipher_init, 1, secretKey);
        // 真正开始加密操作
        jmethodID Cipher_doFinal = env->GetMethodID(Cipher, "doFinal", "([B)[B");
        jbyteArray plainStringBytes = (jbyteArray) env->CallObjectMethod(jstr,
                                                                         String_getBytes,
                                                                         env->NewStringUTF(
                                                                                 charset));
        jbyteArray encryptStr = (jbyteArray) env->CallObjectMethod(cipher, Cipher_doFinal,
                                                                   plainStringBytes);
        //释放对象
        env->DeleteLocalRef(String);
        env->DeleteLocalRef(SecretKeyFactory);
        env->DeleteLocalRef(keyFactory);
        env->DeleteLocalRef(DESKeySpec);
        env->DeleteLocalRef(dks);
        env->DeleteLocalRef(SecretKey);
        env->DeleteLocalRef(Cipher);
        env->DeleteLocalRef(keyByte);
        env->DeleteLocalRef(plainStringBytes);
        if (encryptStr != NULL) {
            //Base64编码
            jclass Base64 = env->FindClass("android/util/Base64");
            jmethodID Base64_encode = env->GetStaticMethodID(Base64, "encodeToString",
                                                             "([BI)Ljava/lang/String;");
            return (jstring) env->CallStaticObjectMethod(Base64, Base64_encode, encryptStr, 2);
        }
    }
    return NULL;

}

JNIEXPORT jstring JNICALL Java_com_jwz_encrypt_EncryptionClient_decryptByDes
        (JNIEnv *env, jclass clzz, jstring jstr) {
    const char *des = "DES";
    const char *desP = "DES/ECB/PKCS5Padding";
    const char *charset = "UTF-8";
    if (jstr != NULL && env->GetStringLength(jstr) > 0) {
        jclass String = env->FindClass("java/lang/String");
        jmethodID String_getBytes = env->GetMethodID(String, "getBytes", "(Ljava/lang/String;)[B");
        jmethodID String_init = env->GetMethodID(String, "<init>", "([BLjava/lang/String;)V");
        // 创建一个密匙工厂
        jclass SecretKeyFactory = env->FindClass("javax/crypto/SecretKeyFactory");
        jmethodID SecretKeyFactory_getInstance = env->GetStaticMethodID(SecretKeyFactory,
                                                                        "getInstance",
                                                                        "(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;");
        jobject keyFactory = env->CallStaticObjectMethod(SecretKeyFactory,
                                                         SecretKeyFactory_getInstance,
                                                         env->NewStringUTF(des));
        // 创建一个DESKeySpec对象
        jclass DESKeySpec = env->FindClass("javax/crypto/spec/DESKeySpec");
        jmethodID DESKeySpec_init = env->GetMethodID(DESKeySpec, "<init>", "([B)V");
        jbyte *by = (jbyte *) key;
        jbyteArray keyByte = env->NewByteArray(64);
        env->SetByteArrayRegion(keyByte, 0, 64, by);
        jobject dks = env->NewObject(DESKeySpec, DESKeySpec_init, keyByte);
        // 将DESKeySpec对象转换成SecretKey对象
        jclass SecretKey = env->FindClass("javax/crypto/SecretKey");
        jmethodID SecretKeyFactory_generateSecret = env->GetMethodID(SecretKeyFactory,
                                                                     "generateSecret",
                                                                     "(Ljava/security/spec/KeySpec;)Ljavax/crypto/SecretKey;");
        jobject secretKey = env->CallObjectMethod(keyFactory, SecretKeyFactory_generateSecret, dks);
        // 用密匙初始化Cipher对象
        jclass Cipher = env->FindClass("javax/crypto/Cipher");
        jmethodID Cipher_getInstance = env->GetStaticMethodID(Cipher,
                                                              "getInstance",
                                                              "(Ljava/lang/String;)Ljavax/crypto/Cipher;");
        jobject cipher = env->CallStaticObjectMethod(Cipher, Cipher_getInstance,
                                                     env->NewStringUTF(desP));
        // Cipher对象实际完成解密操作
        jmethodID Cipher_init = env->GetMethodID(Cipher, "init", "(ILjava/security/Key;)V");
        env->CallVoidMethod(cipher, Cipher_init, 2, secretKey);
        //Base64解码
        jclass Base64 = env->FindClass("android/util/Base64");
        jmethodID Base64_decode = env->GetStaticMethodID(Base64, "decode",
                                                         "(Ljava/lang/String;I)[B");
        jbyteArray text = (jbyteArray) env->CallStaticObjectMethod(Base64, Base64_decode,
                                                                   jstr, 2);

        jstring decodeResult = NULL;

        jthrowable exc = env->ExceptionOccurred();
        if (exc) {
            jclass newExcCls;
            env->ExceptionDescribe();
            env->ExceptionClear();
            newExcCls = env->FindClass("java/lang/Exception");
            env->ThrowNew(newExcCls, "please check input argument, str is not base64");
            env->DeleteLocalRef(newExcCls);
        } else {
            // 真正开始解密操作
            jmethodID Cipher_doFinal = env->GetMethodID(Cipher, "doFinal", "([B)[B");
            jbyteArray decryptBytes = (jbyteArray) env->CallObjectMethod(cipher, Cipher_doFinal, text);

            jthrowable exc = env->ExceptionOccurred();
            if (exc) {
                jclass newExcCls;
                env->ExceptionDescribe();
                env->ExceptionClear();
                newExcCls = env->FindClass("java/lang/Exception");
                env->ThrowNew(newExcCls, "please check input argument, last block incomplete in decryption");
                env->DeleteLocalRef(newExcCls);
            } else {
                if (decryptBytes != NULL) {
                    decodeResult = (jstring) env->NewObject(String, String_init, decryptBytes,
                                                            env->NewStringUTF(charset));
                }
            }
        }

        //释放对象
        env->DeleteLocalRef(SecretKeyFactory);
        env->DeleteLocalRef(keyFactory);
        env->DeleteLocalRef(DESKeySpec);
        env->DeleteLocalRef(dks);
        env->DeleteLocalRef(SecretKey);
        env->DeleteLocalRef(Cipher);
        env->DeleteLocalRef(keyByte);
        env->DeleteLocalRef(Base64);
        env->DeleteLocalRef(text);


        return decodeResult;
    }
    return NULL;
}
