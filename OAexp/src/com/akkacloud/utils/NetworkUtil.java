package com.akkacloud.utils;



import com.sun.deploy.util.StringUtils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static com.akkacloud.utils.HttpsUtils.MyX509TrustManagerUtils;

public class NetworkUtil {
    /**
     *
     * @param url http://www.baidu.com
     * @return
     */
    public static boolean isOk(String url) {
        String trimurl = url.trim();
        if(trimurl == null||trimurl.length()==0) return false;
        Map<String, String> map = new HashMap<>();
        try {
            HashMap<String, Object> respmap = HttpsUtils.sendGet(trimurl, null, map, null);
            Integer code = (Integer) respmap.get("Code");
            if (code==200){
                return true;
            }else {
                return false;
            }


        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        boolean ok = isOk("https://www.baidu.com");
        System.out.println(ok);
    }


}
