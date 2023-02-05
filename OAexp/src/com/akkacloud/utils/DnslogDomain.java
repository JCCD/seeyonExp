package com.akkacloud.utils;

import java.sql.Time;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DnslogDomain {

    public static String getDnslog(){
        try {
            HashMap<String, String> headers = new HashMap<>();
            HashMap<String, Object> resp = HttpsUtils.sendGet("http://dnslog.cn/getdomain.php", null, headers,null);
            Map<String, List<String>> headerFields = (Map<String, List<String>>) resp.get("headerFields");
            String dnslogStr = (String) resp.get("RespBody");
            String cookie = headerFields.get("Set-Cookie").get(0).split(";")[0];
            return cookie+";"+dnslogStr.replace("\r\n", "");
        }catch (Exception e){
            System.out.println("http获取头失败");
            e.printStackTrace();
            return "Error get dnslog!";
        }

    }

    public static Boolean checkDnslog(String cookie,String dnslogStr) throws InterruptedException {
        HashMap<String, String> headers1 = new HashMap<>();
        headers1.put("Cookie", cookie);
        Thread.sleep(3000);
        HashMap<String, Object> resp1 = HttpsUtils.sendGet("http://dnslog.cn/getrecords.php", null, headers1,null);
        String respBody1 = (String) resp1.get("RespBody");
        if (respBody1.contains(dnslogStr)){
            return true;
        }
        return false;
    }



}
