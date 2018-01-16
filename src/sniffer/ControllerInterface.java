package sniffer;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;

public class ControllerInterface implements Initializable {
	ObservableList devs;
	List<PcapIf> alldevs;
	StringBuilder errbuf;
	PcapIf device = null;
	@FXML
	private ListView<PcapIf> interfaces;
	private Application app;

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		// 初始化时获取所有网卡的信息
		alldevs = new ArrayList<PcapIf>();
		errbuf = new StringBuilder();
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.out.println("Can't read list of devices. " + errbuf);
		}
		devs = FXCollections.observableList(alldevs);
		// 为这个ListView设置数据源
		interfaces.setItems(devs);
		interfaces.setCellFactory((ListView<PcapIf> list) -> new Interface());
		// 设置监听的点击事件
		interfaces.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {
			device = newValue;
		});
	}

	public PcapIf getInterface() {
		return device;
	}

	@FXML
	public void Select() {
		interfaces.getScene().getWindow().hide();
	}

	class Interface extends ListCell<PcapIf> {
		protected void updateItem(PcapIf item, boolean empty) {
			super.updateItem(item, empty);
			setGraphic(null);
			setText(null);
			if (item != null) {
				HBox hBox = new HBox();
				Text desc = new Text(item.getDescription());// 网卡信息
				// 网卡地址
				String addr = item.getAddresses().toString();
				Text padding = new Text(":      ");
				// 对地址字符串进行分割获取我们需要的字符串
				System.out.println("addr:" + addr);
				Text address = new Text(addr.split("]")[0].split("\\[")[3]);
				hBox.getChildren().addAll(desc, padding, address);
				setGraphic(hBox);
			}
		}

	}
}