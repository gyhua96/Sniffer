package sniffer;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

public class ControllerInterface implements Initializable{
    ObservableList devs;
    List<PcapIf> alldevs;
    StringBuilder errbuf;
    PcapIf device=null;
    @FXML private ListView<PcapIf> interfaces;
    private Application app;

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        alldevs = new ArrayList<PcapIf>();
        errbuf = new StringBuilder();
        int r= Pcap.findAllDevs(alldevs,errbuf);
        if(r==Pcap.NOT_OK||alldevs.isEmpty()){
            System.out.println("Can't read list of devices. "+errbuf);
        }
        devs= FXCollections.observableList(alldevs);
        interfaces.setItems(devs);
        interfaces.setCellFactory((ListView<PcapIf> list)->new Interface());
        interfaces.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
            device=newValue;
        });
    }
    public PcapIf getInterface(){
        return device;
    }
    @FXML
    public void Select(){
        interfaces.getScene().getWindow().hide();
    }
    class Interface extends ListCell<PcapIf>{
        protected void updateItem(PcapIf item,boolean empty){
            super.updateItem(item,empty);
            setGraphic(null);
            setText(null);
            if(item!=null){
                HBox hBox=new HBox();
                Text desc=new Text(item.getDescription());
                String addr=item.getAddresses().toString();
                Text address=new Text(addr.split("]")[0].split("\\[")[3]);
                Text padding=new Text(":      ");
                hBox.getChildren().addAll(desc,padding,address);
                setGraphic(hBox);
            }
        }

    }
}
