package com.akkacloud.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RexUtil {
    /**
     * 正则表达式匹配两个指定字符串中间的内容
     * @param soap
     * @return
     */
    public static List<String> getSubUtil(String soap,String rgex){
        List<String> list = new ArrayList<String>();
        Pattern pattern = Pattern.compile(rgex);// 匹配的模式
        Matcher m = pattern.matcher(soap);
        while (m.find()) {
            int i = 1;
            list.add(m.group(i));
            i++;
        }
        return list;
    }

    /**
     * 匹配两个字符之间的
     * 返回单个字符串，若匹配到多个的话就返回第一个，方法与getSubUtil一样
     * @param soap
     * @param rgex
     * @return
     */
    public static String getSubUtilSimple(String soap,String rgex){
        Pattern pattern = Pattern.compile(rgex);// 匹配的模式
        Matcher m = pattern.matcher(soap);
        while(m.find()){
            return m.group(1);//m.group(1)不包括这两个字符
        }
        return "";
    }

    /**
     * 测试
     * @param args
     */
    public static void main(String[] args) {


        /*String filetext = "fileurls=fileurls+\",\"+'5685646482015339269';";
        System.out.println(filetext);
        Pattern p = Pattern.compile("fileurls\\+\"\\,\"\\+\\'(.*?)\\'\\;");

        Matcher m = p.matcher(filetext);
        while(m.find()) {
            System.out.println(m.group(1));//m.group(1)不包括这两个字符

        }*/
        String filetext = "fileurls=fileurls+\",\"+'5685646488882015339269';";
        String rgex = "fileurls\\+\"\\,\"\\+\\'(.*?)\\'\\;";
        String subUtilSimple = RexUtil.getSubUtilSimple(filetext, rgex);
        System.out.println(subUtilSimple);


    }
}
