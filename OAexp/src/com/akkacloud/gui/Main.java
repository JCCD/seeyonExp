package com.akkacloud.gui;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception{

        FXMLLoader fxmlLoader = new FXMLLoader();
        /*导入fxml视图*/
        fxmlLoader.setLocation(getClass().getResource("OAEXP.fxml"));

        /*获取根节点*/
        Parent root  = fxmlLoader.load();
        /*创建场景放入根节点(布局)*/
        Scene scene = new Scene(root);
/*
        *//*获取controller*//*
        OAController controller = fxmlLoader.getController();
        *//*调用controller方法设置节点*//*
        controller.TextAreaBind(scene);*/

        primaryStage.setTitle("OAEXP by akka");
        primaryStage.setScene(scene);
        primaryStage.show();


    }


    public static void main(String[] args) {
        launch(args);
    }
}
