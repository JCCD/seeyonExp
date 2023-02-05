package com.akkacloud.utils;

import com.akkacloud.gui.OAController;

import java.io.*;
import java.net.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

public class HttpsUtils {



    public static void main(String[] args) {




    }

    //设置请求头属性
    public static Map<String, String> setProperty(Map<String, String> Header) {
        return Header;
    }

    /**
     * GET请求
     *
     * @param url
     *            请求的URL
     * @param param
     *            请求参数，name1=value1&name2=value2 的形式
     * @return 响应结果
     */
    public static HashMap<String, Object> sendGet(String url, String param,Map<String,String> header ,String encoding) {
        String result = "";
        BufferedReader in = null;
        HashMap<String, Object> resp =null;
        Map<String, List<String>> headerFields =null;
        try {
            String urlNameString = url;
            if (param != null && !("".equals(param)))
                urlNameString = url + "?" + param;
            URL realUrl = new URL(urlNameString);
            // 打开和URL之间的连接
            HttpURLConnection connection = null;
            if (OAController.Proxy.get("Status").equals("openProxy")) {// 使用代理模式
                @SuppressWarnings("static-access")
                Proxy proxy = new Proxy(Proxy.Type.DIRECT.HTTP, new InetSocketAddress(OAController.Proxy.get("IP"), Integer.parseInt(OAController.Proxy.get("Port"))));
                connection = (HttpURLConnection) realUrl.openConnection(proxy);
            } else {
                connection = (HttpURLConnection) realUrl.openConnection();
            }

            // https 忽略证书验证
            if (url.substring(0, 5).equals("https")) {
                SSLContext ctx = MyX509TrustManagerUtils();
                ((HttpsURLConnection) connection).setSSLSocketFactory(ctx.getSocketFactory());
                ((HttpsURLConnection) connection).setHostnameVerifier(new HostnameVerifier() {
                    @Override
                    public boolean verify(String arg0, SSLSession arg1) {
                        return true;
                    }
                });
            }



            //设置http必备的头
            header.put("connection", "close");
            header.put("user-agent", UserAgentUtil.getRandomUserAgent());
            if(header.get("Content-Type")==null||header.get("Content-Type").equals("")){
                header.put("Content-Type", "application/x-www-form-urlencoded");
            }

            // 设置通用的请求属性
            for (Map.Entry<String, String> entry : setProperty(header).entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
            }
            connection.setReadTimeout(10000);/*10s*/
            // 建立连接
            connection.connect();
            if (encoding==null||encoding.equals("")) {
                encoding = "UTF-8";
            }
            // 定义BufferedReader输入流来读取URL的响应
            try {
                if (connection.getResponseCode() == HttpURLConnection.HTTP_OK
                        || connection.getResponseCode() == HttpURLConnection.HTTP_CREATED
                        || connection.getResponseCode() == HttpURLConnection.HTTP_ACCEPTED) {
                    in = new BufferedReader(new InputStreamReader(connection.getInputStream(), encoding));

                } else {
                    in = new BufferedReader(new InputStreamReader(connection.getErrorStream(), encoding));
                }
                String line;
                while ((line = in.readLine()) != null) {
                    result += line+"\r\n";
                }
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

            resp = new HashMap<>();
            /*获取返回头*/
            headerFields = connection.getHeaderFields();
            resp.put("headerFields",headerFields);
            resp.put("Code", connection.getResponseCode());
            resp.put("RespBody",result);
        } catch (Exception e) {
            System.out.println("发送GET请求出现异常！");
            e.printStackTrace();
        }
        // 使用finally块来关闭输入流
        finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return resp;
    }

    public static HashMap<String, Object> sendPost(String url, String param, Map<String,String> header){
        return sendPost(url, param, header, null);
    }
    /**
     * POST请求
     *
     * @param url 发送请求的 URL
     *
     * @param param 请求参数 name1=value1&name2=value2 的形式

     *
     * @param header 请求头
     *
     * @return 响应结果
     */
    public static HashMap<String, Object> sendPost(String url, String param, Map<String,String> header,String encoding) {
        OutputStreamWriter out = null;
        BufferedReader in = null;
        HashMap<String, Object> resp =null;
        Map<String, List<String>> headerFields =null;
        String result = "";
        try {
            URL realUrl = new URL(url);
            HttpURLConnection conn = null;
            if (OAController.Proxy.get("Status").equals("openProxy")) {// 使用代理模式
                @SuppressWarnings("static-access")
                Proxy proxy = new Proxy(Proxy.Type.DIRECT.HTTP, new InetSocketAddress(OAController.Proxy.get("IP"), Integer.parseInt(OAController.Proxy.get("Port"))));
                conn = (HttpURLConnection) realUrl.openConnection(proxy);
            } else {
                conn = (HttpURLConnection) realUrl.openConnection();
            }

            // https
            if (url.substring(0, 5).equals("https")) {
                SSLContext ctx = MyX509TrustManagerUtils();
                ((HttpsURLConnection) conn).setSSLSocketFactory(ctx.getSocketFactory());
                ((HttpsURLConnection) conn).setHostnameVerifier(new HostnameVerifier() {
                    //在握手期间，如果 URL 的主机名和服务器的标识主机名不匹配，则验证机制可以回调此接口的实现程序来确定是否应该允许此连接。
                    @Override
                    public boolean verify(String arg0, SSLSession arg1) {
                        return true;
                    }
                });
            }

            // 发送POST请求必须设置如下两行
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestMethod("POST"); // POST方法

            // 设置通用的请求属性

            // pMap.put("Accept-Encoding", "gzip"); //请求定义gzip,响应也是压缩包
            header.put("connection", "close");
            header.put("user-agent", UserAgentUtil.getRandomUserAgent());
            if(header.get("Content-Type")==null||header.get("Content-Type").equals("")){
                header.put("Content-Type", "application/x-www-form-urlencoded");
            }
            for (Map.Entry<String, String> entry : setProperty(header).entrySet()) {
                conn.setRequestProperty(entry.getKey(), entry.getValue());
            }

            conn.setReadTimeout(10000);
            conn.connect();

            if (encoding==null||encoding.equals("")) {
                encoding = "GBK";
            }

            // 获取URLConnection对象对应的输出流
            out = new OutputStreamWriter(conn.getOutputStream(), encoding);
            // 发送请求参数
            out.write(param);
            // flush输出流的缓冲
            out.flush();
            // 定义BufferedReader输入流来读取URL的响应
            try {
                if (conn.getResponseCode() == HttpURLConnection.HTTP_OK
                        || conn.getResponseCode() == HttpURLConnection.HTTP_CREATED
                        || conn.getResponseCode() == HttpURLConnection.HTTP_ACCEPTED) {
                    in = new BufferedReader(new InputStreamReader(conn.getInputStream(), encoding));

                } else {
                    in = new BufferedReader(new InputStreamReader(conn.getErrorStream(), encoding));
                }
                String line;
                while ((line = in.readLine()) != null) {
                    result += line+"\r\n";
                }
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            resp = new HashMap<>();
            /*获取返回头*/
            headerFields = conn.getHeaderFields();
            resp.put("headerFields",headerFields);
            resp.put("Code", conn.getResponseCode());
            resp.put("RespBody",result);


        } catch (Exception e) {
            System.out.println("发送 POST 请求出现异常！");
            e.printStackTrace();
        }
        // 使用finally块来关闭输出流、输入流
        finally {
            try {
                if (out != null) {
                    out.close();
                }
                if (in != null) {
                    in.close();
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return resp;
    }

    /**
     *
     * @param url 上传接口
     * @param isproxy 代理
     * @param header request头部设置
     * @param params requestBody的参数设置
     * @return
     */
    public static String uploadFile(String url, boolean isproxy, Map<String,String> header,Map<String,String>params,String uploadFile) {
        String end = "\r\n";
        String twoHyphens = "--";
        String boundary = "d4a59f8bf0e77833d051c43bb642129b";
        OutputStreamWriter out = null;
        DataOutputStream ds = null;
        BufferedReader in = null;
        String result = "";
        try {
            URL realUrl = new URL(url);
            HttpURLConnection conn = null;
            if (OAController.Proxy.get("Status").equals("openProxy")) {// 使用代理模式
                @SuppressWarnings("static-access")
                Proxy proxy = new Proxy(Proxy.Type.DIRECT.HTTP, new InetSocketAddress(OAController.Proxy.get("IP"), Integer.parseInt(OAController.Proxy.get("Port"))));
                conn = (HttpURLConnection) realUrl.openConnection(proxy);
            } else {
                conn = (HttpURLConnection) realUrl.openConnection();
            }

            // https
            if (url.substring(0, 5).equals("https")) {
                SSLContext ctx = MyX509TrustManagerUtils();
                ((HttpsURLConnection) conn).setSSLSocketFactory(ctx.getSocketFactory());
                ((HttpsURLConnection) conn).setHostnameVerifier(new HostnameVerifier() {
                    //在握手期间，如果 URL 的主机名和服务器的标识主机名不匹配，则验证机制可以回调此接口的实现程序来确定是否应该允许此连接。
                    @Override
                    public boolean verify(String arg0, SSLSession arg1) {
                        return true;
                    }
                });
            }

            // 发送POST请求必须设置如下两行
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestMethod("POST"); // POST方法

            // 设置通用的请求属性

            // pMap.put("Accept-Encoding", "gzip"); //请求定义gzip,响应也是压缩包
            header.put("connection", "close");
            header.put("user-agent", UserAgentUtil.getRandomUserAgent());
            if(header.get("Content-Type")==null||header.get("Content-Type").equals("")){
                header.put("Content-Type", "multipart/form-data; boundary="+boundary);
            }
            for (Map.Entry<String, String> entry : setProperty(header).entrySet()) {
                conn.setRequestProperty(entry.getKey(), entry.getValue());
            }

            // 设置DataOutputStream
            ds = new DataOutputStream(conn.getOutputStream());

            String filename = "akka.png";

            //======传递参数======
            Iterator it=params.entrySet().iterator();
            while (it.hasNext()){
                Map.Entry param = (Map.Entry)it.next();
                ds.writeBytes(twoHyphens + boundary + end);
                StringBuffer c = new StringBuffer();
                c.append("Content-Disposition: form-data; name=\"");
                c.append(param.getKey().toString());
                c.append("\"");
                c.append(end);
                c.append(end);
                c.append(param.getValue().toString());
                c.append(end);
                ds.writeBytes(c.toString());
            }
            //======传递参数end======
            //======传递文件======
            ds.writeBytes(twoHyphens + boundary + end);
            ds.writeBytes("Content-Disposition: form-data; " + "name=\"files" + "\";filename=\"" + filename+ "\"" + end);
            ds.writeBytes("Content-Type: image/png "+ end);
            ds.writeBytes(end);
            FileInputStream fStream = new FileInputStream(uploadFile);
            int bufferSize = 1024;
            byte[] buffer = new byte[bufferSize];
            int length = -1;
            while ((length = fStream.read(buffer)) != -1) {
                ds.write(buffer, 0, length);
            }
            ds.writeBytes(end);
            //======传递文件end======
            fStream.close();
            ds.writeBytes(twoHyphens + boundary + twoHyphens + end);
            ds.flush();

            conn.setReadTimeout(10000);
            conn.connect();
            // 定义BufferedReader输入流来读取URL的响应
            try {
                if (conn.getResponseCode() == HttpURLConnection.HTTP_OK
                        || conn.getResponseCode() == HttpURLConnection.HTTP_CREATED
                        || conn.getResponseCode() == HttpURLConnection.HTTP_ACCEPTED) {
                    in = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));

                } else {
                    in = new BufferedReader(new InputStreamReader(conn.getErrorStream(), "UTF-8"));
                }
                String line;
                while ((line = in.readLine()) != null) {
                    result += line;
                }
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            if (ds != null) {
                try {
                    ds.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }


        return result;
    }




    // ===========================utils===================

    /**
     * url编码
     *
     * @param source
     *            待编码字符串
     * @param encode
     *            字符编码 eg:UTF-8
     * @return 编码字符串
     */
    public static String urlEncode(String source, String encode) {
        String result = source;
        try {
            result = java.net.URLEncoder.encode(source, encode);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return "0";
        }
        return result;
    }

    /*
     * HTTPS忽略证书验证,防止高版本jdk因证书算法不符合约束条件,使用继承X509ExtendedTrustManager的方式
     */
    class MyX509TrustManager extends X509ExtendedTrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
            // TODO Auto-generated method stub

        }

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
            // TODO Auto-generated method stub

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            // TODO Auto-generated method stub
            return null;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1, Socket arg2) throws CertificateException {
            // TODO Auto-generated method stub

        }

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1, SSLEngine arg2)
                throws CertificateException {
            // TODO Auto-generated method stub

        }

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1, Socket arg2) throws CertificateException {
            // TODO Auto-generated method stub

        }

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1, SSLEngine arg2)
                throws CertificateException {
            // TODO Auto-generated method stub

        }

    }

    public static SSLContext MyX509TrustManagerUtils() {

        TrustManager[] tm = { new HttpsUtils().new MyX509TrustManager() };
        SSLContext ctx = null;
        try {
            ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tm, null);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ctx;
    }

}
