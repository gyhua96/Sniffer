package sniffer;

import java.net.URL;
import java.util.ResourceBundle;

import javafx.event.Event;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.CheckBox;
import javafx.stage.WindowEvent;

public class ControllerFlitter implements Initializable {
	boolean http = true;
	boolean icmp = true;
	boolean arp = true;
	boolean tcp = true;
	boolean ip4 = true;
	boolean udp = true;
	boolean ip6 = true;
	@FXML
	private CheckBox checkHttp;
	@FXML
	private CheckBox checkIcmp;
	@FXML
	private CheckBox checkArp;
	@FXML
	private CheckBox checkTcp;
	@FXML
	private CheckBox checkUdp;
	@FXML
	private CheckBox checkIp4;
	@FXML
	private CheckBox checkIp6;
	private ControllerMain ctrlMain;

	@Override
	public void initialize(URL location, ResourceBundle resources) {

	}

	// setMainController 这里设置这个的目的是为了调用mainPane里面的方法
	public void setMainController(ControllerMain ctrlMain) {
		this.ctrlMain = ctrlMain;
	}

	// 发生改变的时候调用这个方法
	@FXML
	private void change() {
		http = checkHttp.isSelected();
		tcp = checkTcp.isSelected();
		udp = checkUdp.isSelected();
		icmp = checkIcmp.isSelected();
		arp = checkArp.isSelected();
		ip4 = checkIp4.isSelected();
		ip6 = checkIp6.isSelected();
		// choiceChanged.setValue(false);
		ctrlMain.flitterChanged();
		Event.fireEvent(checkArp.getScene().getWindow(),
				new WindowEvent(checkArp.getScene().getWindow(), WindowEvent.WINDOW_CLOSE_REQUEST));
	}

	public boolean isArp() {
		return arp;
	}

	public boolean isHttp() {
		return http;
	}

	public boolean isIcmp() {
		return icmp;
	}

	public boolean isIp4() {
		return ip4;
	}

	public boolean isIp6() {
		return ip6;
	}

	public boolean isTcp() {
		return tcp;
	}

	public boolean isUdp() {
		return udp;
	}
}
