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
package com.jwz.encrypt.gzip;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * @author jiangwenzhong
 * @date 2018/12/21
 */
public class GzipUtils {

    /**
     * 字符串的压缩
     *
     * @param str 待压缩的字符串
     *
     * @return 返回压缩后的字符串
     */
    public static String compress(String str) {

        if (null == str || str.length() <= 0) {
            return "";
        }
        ByteArrayOutputStream out = null;
        GZIPOutputStream gzip = null;
        try {
            // 创建一个新的 byte 数组输出流
            out = new ByteArrayOutputStream();
            // 使用默认缓冲区大小创建新的输出流
            gzip = new GZIPOutputStream(out);
            // 将 b.length 个字节写入此输出流
            gzip.write(str.getBytes());
            gzip.close();
            // 使用指定的 charsetName，通过解码字节将缓冲区内容转换为字符串
            return out.toString("UTF-8");
        } catch (IOException exception) {
            exception.printStackTrace();
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (gzip != null) {
                try {
                    gzip.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return "";
    }

    /**
     * 字符串的解压
     *
     * @param str 对字符串解压
     *
     * @return 返回解压缩后的字符串
     */
    public static String unCompress(String str) {

        if (null == str || str.length() <= 0) {
            return str;
        }
        return unCompress(str);
    }

    /**
     * 字符串的解压
     *
     * @param str 对字符串解压
     *
     * @return 返回解压缩后的字符串
     */
    public static String unCompress(byte[] str) {

        if (null == str || str.length <= 0) {
            return "";
        }
        ByteArrayOutputStream out = null;
        GZIPInputStream gzip = null;

        try {
            // 创建一个新的 byte 数组输出流
            out = new ByteArrayOutputStream();
            // 创建一个 ByteArrayInputStream，使用 buf 作为其缓冲区数组
            ByteArrayInputStream in = new ByteArrayInputStream(str);
            // 使用默认缓冲区大小创建新的输入流
            gzip = new GZIPInputStream(in);
            byte[] buffer = new byte[256];
            int n = 0;
            // 将未压缩数据读入字节数组
            while ((n = gzip.read(buffer)) >= 0) {
                // 将指定 byte 数组中从偏移量 off 开始的 len 个字节写入此 byte数组输出流
                out.write(buffer, 0, n);
            }
            // 使用指定的 charsetName，通过解码字节将缓冲区内容转换为字符串
            return out.toString("UTF-8");
        } catch (IOException exception) {
            exception.printStackTrace();
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (gzip != null) {
                try {
                    gzip.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return "";
    }

    public static boolean isGzip(byte[] dataArr) {

        if (dataArr == null || dataArr.length <= 0) {
            return false;
        }
        int b0 = dataArr[0];
        int b1 = dataArr[1];

        int b = ((b1 & 0xFF) << 8 | b0);
        return b == GZIPInputStream.GZIP_MAGIC;
    }
}
