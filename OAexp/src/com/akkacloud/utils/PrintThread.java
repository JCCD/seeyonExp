package com.akkacloud.utils;

import com.akkacloud.gui.OAController;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.TextArea;

import java.util.concurrent.ExecutorService;

public class PrintThread extends Thread {

    private final OAController mainController;;
    private String s;

    public PrintThread(OAController main, String s) {
        this.mainController = main;
        this.s = s;
    }

    public void run() {
        // 注意，这里不属于swing主线程，所以appendText的内容才会被刷新
        Platform.runLater(new Runnable() {
            @Override
            public void run() {
                try {
                    sleep(1000);

                }catch (RuntimeException | InterruptedException e){

                    e.printStackTrace();
                }
                mainController.infoText.appendText(s + "\n");

            }
        });


    }

}
