module com.example.sec_lab_3 {
    requires javafx.controls;
    requires javafx.fxml;
    requires lombok;


    opens com.example.sec_lab_4 to javafx.fxml;
    exports com.example.sec_lab_4;
}