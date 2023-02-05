package com.akkacloud.gui;

import javafx.beans.property.BooleanProperty;
import javafx.collections.ObservableMap;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.util.HashMap;
import java.util.Map;

public class proxyController {
    @FXML
    private RadioButton openProxy;

    @FXML
    private RadioButton CloseProxy;

    @FXML
    private ToggleGroup proxyStatus;

    @FXML
    private TextField proxyIP;

    @FXML
    private TextField proxyPort;

    @FXML
    private Button saveProxyBtn;

    @FXML
    private Button closeProxyBtn;



    @FXML
    void closeProxy(ActionEvent event) {
        Stage stage = (Stage) closeProxyBtn.getScene().getWindow();
        stage.close();
    }
    @FXML
    void saveProxy(ActionEvent event) {
        RadioButton selectedRadioButton = (RadioButton) proxyStatus.getSelectedToggle();
        String Status = selectedRadioButton.getId();
        String IP = proxyIP.getText();
        String Port = proxyPort.getText();
        OAController.Proxy.put("Status",Status);
        OAController.Proxy.put("IP",IP);
        OAController.Proxy.put("Port",Port);
        Stage stage = (Stage) saveProxyBtn.getScene().getWindow();
        stage.close();
    }
    public void initialize(){
        /*初始化是给下拉列表赋值表并且设置默认选项*/
        proxyIP.setText("127.0.0.1");
        proxyPort.setText("8080");

        if(OAController.Proxy.get("Status").equals("openProxy")){
            openProxy.setSelected(true);
        }else {
            CloseProxy.setSelected(true);
        }







    }
}
