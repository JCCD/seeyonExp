package com.akkacloud.utils;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;

public class CommonsUtils {
    private static String TableBase64 = "gx74KW1roM9qwzPFVOBLSlYaeyncdNbI=JfUCQRHtj2+Z05vshXi3GAEuT/m8Dpk6";
    private static String FError = new String();
    public static String Charset = "GB2312";

    public static String normizePath(String path) throws Exception{
        if (path.startsWith("/")){
            return path.substring(1, path.length());
        } else {
            return path;
        }
    }

    public static String normizeUrl(String url) throws Exception {
        if (url.endsWith("/")){
            return url;
        } else {
            return url + "/";
        }
    }

    public static String DecodeBase64(String var1) {
        ByteArrayOutputStream var2 = new ByteArrayOutputStream();
        String var3 = "";
        byte[] var8 = new byte[4];

        try {
            int var5 = 0;
            byte[] var7 = var1.getBytes();

            while(var5 < var7.length) {
                for(int var4 = 0; var4 <= 3; ++var4) {
                    if (var5 >= var7.length) {
                        var8[var4] = 64;
                    } else {
                        int var6 = TableBase64.indexOf(var7[var5]);
                        if (var6 < 0) {
                            var6 = 65;
                        }

                        var8[var4] = (byte)var6;
                    }

                    ++var5;
                }

                var2.write((byte)(((var8[0] & 63) << 2) + ((var8[1] & 48) >> 4)));
                if (var8[2] != 64) {
                    var2.write((byte)(((var8[1] & 15) << 4) + ((var8[2] & 60) >> 2)));
                    if (var8[3] != 64) {
                        var2.write((byte)(((var8[2] & 3) << 6) + (var8[3] & 63)));
                    }
                }
            }
        } catch (StringIndexOutOfBoundsException var11) {
            FError = FError + var11.toString();
            System.out.println(var11.toString());
        }

        try {
            var3 = var2.toString(Charset);
        } catch (UnsupportedEncodingException var10) {
            System.out.println(var10.toString());
        }

        return var3;
    }

    public static String EncodeBase64(String var1) {
        ByteArrayOutputStream var2 = new ByteArrayOutputStream();
        byte[] var7 = new byte[4];

        try {
            int var4 = 0;
            byte[] var6 = var1.getBytes(Charset);

            while(var4 < var6.length) {
                byte var5 = var6[var4];
                ++var4;
                var7[0] = (byte)((var5 & 252) >> 2);
                var7[1] = (byte)((var5 & 3) << 4);
                if (var4 < var6.length) {
                    var5 = var6[var4];
                    ++var4;
                    var7[1] += (byte)((var5 & 240) >> 4);
                    var7[2] = (byte)((var5 & 15) << 2);
                    if (var4 < var6.length) {
                        var5 = var6[var4];
                        ++var4;
                        var7[2] = (byte)(var7[2] + ((var5 & 192) >> 6));
                        var7[3] = (byte)(var5 & 63);
                    } else {
                        var7[3] = 64;
                    }
                } else {
                    var7[2] = 64;
                    var7[3] = 64;
                }

                for(int var3 = 0; var3 <= 3; ++var3) {
                    var2.write(TableBase64.charAt(var7[var3]));
                }
            }
        } catch (StringIndexOutOfBoundsException var10) {
            FError = FError + var10.toString();
            System.out.println(var10.toString());
        } catch (UnsupportedEncodingException var11) {
            System.out.println(var11.toString());
        }

        return var2.toString();
    }




}
