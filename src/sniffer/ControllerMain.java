package sniffer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;
import javafx.scene.text.TextAlignment;
import javafx.stage.Stage;

public class ControllerMain implements Initializable {
	@FXML
	private MenuBar menuBar;
	@FXML
	private MenuItem fileSave;
	@FXML
	private MenuItem selectInterface;
	@FXML
	private MenuItem startSniffer;
	@FXML
	private MenuItem flitters;
	@FXML
	private ListView<PcapPacket> listPackets;// 这里是一个ListView 也就是相当于Android里的ListView,或者RecyclerView
	@FXML
	private MenuItem stopSniffer;
	@FXML
	private TextArea dataDump;
	@FXML
	private Label tcpPacket;
	@FXML
	private Label udpPacket;
	@FXML
	private Label totalPacket;
	@FXML
	private Label icmpPacket;
	@FXML
	private Label httpPacket;
	@FXML
	private Label ipv4Packet;
	@FXML
	private Label ipv6Packet;
	@FXML
	private Label arpPacket;
	@FXML
	private Label otherPacket;
	private long tcpN = 0;
	private long udpN = 0;
	private long totalN = 0;
	private long httpN = 0;
	private long arpN = 0;
	private long icmpN = 0;
	private long ipv4N = 0;
	private long ipv6N = 0;
	private long otherN = 0;
	FXMLLoader fxmlLoaderInterface;
	FXMLLoader fxmlLoaderFlitter;
	// 两个弹窗的控制类
	ControllerInterface CtrlInterf;
	ControllerFlitter CtrlFlitter;
	Stage stage = null;
	StringBuilder errbuf = new StringBuilder();
	Thread snifferThread = null;
	private PcapIf device = null;
	// 下面是两个比较重要的集合类
	volatile ObservableList<PcapPacket> packets = FXCollections.observableArrayList();
	ObservableList<PcapPacket> packetsShow = FXCollections.observableArrayList();
	boolean http = true;
	boolean icmp = true;
	boolean arp = true;
	boolean tcp = true;
	boolean ip4 = true;
	boolean udp = true;
	boolean ip6 = true;

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		packetsShow.add(new PcapPacket(0));
		// 为主界面调用的两个对话框加载视图
		fxmlLoaderInterface = new FXMLLoader(getClass().getResource("interface.fxml"));
		fxmlLoaderFlitter = new FXMLLoader(getClass().getResource("flitter.fxml"));

		CtrlInterf = fxmlLoaderInterface.getController();
		// 获取视图的控制器
		// 下面是选择硬件视图的设置
		Parent interfaces = null;
		try {
			interfaces = fxmlLoaderInterface.load();
		} catch (IOException e) {
			e.printStackTrace();
		}
		// 这里是硬件视图整体的stage...然后往里面塞了一个scene..这个scene也就是我们刚刚加载的那个视图
		final Stage stageInterface = new Stage();
		stageInterface.setScene(new Scene(interfaces));
		stageInterface.setTitle("选择网络设备");
		// 下面是选择筛选协议的视图的设置
		Parent flitter = null;
		try {
			flitter = fxmlLoaderFlitter.load();
		} catch (IOException e) {
			e.printStackTrace();
		}
		// 这里是选择筛选协议类型的stage
		final Stage stageFlitter = new Stage();
		stageFlitter.setScene(new Scene(flitter));
		stageFlitter.setTitle("选择筛选协议");
		CtrlFlitter = fxmlLoaderFlitter.getController();
		// 获取视图的控制器
		// ----------------------
		// ----------------------
		// ----------------------
		// ----------------------
		// 视图基本设置完毕，下面需要将两个子视图加载到主界面里去
		CtrlFlitter.setMainController(this);
		// lambe表达式 里面是数据改动之后自动执行的代码，也就是我们常说的 观察者模式
		packets.addListener((ListChangeListener<PcapPacket>) c -> {
			PcapPacket item = packets.get(packets.size() - 1);// 获取最新的数据包
			// 延迟执行
			Platform.runLater(new Runnable() {
				@Override
				public void run() {
					// 更新我们获取到的包的数量
					tcpPacket.setText("" + tcpN);
					udpPacket.setText("" + udpN);
					totalPacket.setText("" + totalN);
					icmpPacket.setText("" + icmpN);
					arpPacket.setText("" + arpN);
					httpPacket.setText("" + httpN);
					ipv4Packet.setText("" + ipv4N);
					ipv6Packet.setText("" + ipv6N);
					otherPacket.setText(totalN - tcpN - udpN - icmpN - ipv4N - ipv6N - arpN - httpN + "");
				}
			});
			synchronized (this) {
				// 下面是判断我们抓取的包的类型...前面的boolean 值是用于过滤我们需要的包
				if (http && item.hasHeader(new Http())) {
					totalN++;
					httpN++;
					packetsShow.add(item);// 这里不调用就无法更新视图
					return;
				}
				if (icmp && item.hasHeader(new Icmp())) {
					totalN++;
					icmpN++;
					packetsShow.add(item);
					return;
				}
				if (tcp && item.hasHeader(new Tcp())) {
					totalN++;
					tcpN++;
					packetsShow.add(item);
					return;
				}
				if (udp && item.hasHeader(new Udp())) {
					totalN++;
					udpN++;
					packetsShow.add(item);
					return;
				}

				if (ip4 && item.hasHeader(new Ip4())) {
					totalN++;
					ipv4N++;
					packetsShow.add(item);
					return;
				}
				if (ip6 && item.hasHeader(new Ip6())) {
					totalN++;
					ipv6N++;
					packetsShow.add(item);
					return;
				}
				if (arp && item.hasHeader(new Arp())) {
					totalN++;
					arpN++;
					packetsShow.add(item);
				}
			} // 同步方法结束,这里是只能异步访问

		});// 添加监听器结束
			// 设置ListView的数据来源
		listPackets.setItems(packetsShow);
		listPackets.setCellFactory((ListView<PcapPacket> item) -> new packetCell());
		// 设置选择listview的一个item的监听器
		listPackets.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<PcapPacket>() {
			@Override
			public void changed(ObservableValue<? extends PcapPacket> observable, PcapPacket oldValue,
					PcapPacket newValue) {
				if (packetsShow.indexOf(newValue) == 0) {
					return;
				}
				dataDump.setText(newValue.toHexdump());
			}
		});
		// 设置两个menuitem的点击事件
		selectInterface.setOnAction(new EventHandler<javafx.event.ActionEvent>() {
			@Override
			public void handle(javafx.event.ActionEvent event) {
				stageInterface.show();
			}
		});
		flitters.setOnAction(new EventHandler<javafx.event.ActionEvent>() {
			@Override
			public void handle(javafx.event.ActionEvent event) {
				stageFlitter.show();
			}
		});
		// 设置停止和开始嗅探的点击事件
		stopSniffer.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {

				if (snifferThread != null) {
					snifferThread.stop();
					snifferThread = null;
					// System.out.println("stop sniffer");
				}
			}
		});
		startSniffer.setOnAction(new EventHandler<javafx.event.ActionEvent>() {
			@Override
			public void handle(javafx.event.ActionEvent event) {
				CtrlInterf = fxmlLoaderInterface.getController();
				// 判断是否选择了网络设备 如果点击过选择网络设备那么CtrlInterf不为空,选择了某个网络设备之后CtrlInterf.getInterf不为空
				// 所以这里需要对两个都进行判断
				if (CtrlInterf == null || CtrlInterf.getInterface() == null) {
					Alert DevNotSelected = new Alert(Alert.AlertType.WARNING);
					DevNotSelected.setTitle("网络设备无效");
					DevNotSelected.setHeaderText("请选择一个网络设备！");
					DevNotSelected.setContentText("未选择网络设备或网络设备无效！");
					DevNotSelected.show();
				} else {// 开始嗅探
					snifferThread = new Thread(() -> {
						// 获取到我们选择的网络设备
						device = CtrlInterf.getInterface();
						// 设置我们选择的嗅探模式
						int snaplen = 64 * 1024;// 最大长度
						int flags = Pcap.MODE_PROMISCUOUS;// 混杂模式
						int timeout = 3 * 1000;// 超时时间
						// 打开设备
						Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
						if (pcap == null) {
							System.out.println("Error while opening device for capture." + errbuf);
						}
						// 设置我们嗅探的处理过程
						PcapPacketHandler<String> pcapPacketHandler = new PcapPacketHandler<String>() {
							@Override
							public void nextPacket(PcapPacket pcapPacket, String s) {
								// 只接受ipv4 或则arp头的协议..这里应该修改下，不应该先判断再添加，直接添加
								// if (pcapPacket.hasHeader(new Ip4()) || pcapPacket.hasHeader(new Arp())) {
								// packets.add(pcapPacket);
								// 每嗅探到一个包，我们把放在添加到这个observbleList里，触发这个Ob
								// 的listener
								// }
								packets.add(pcapPacket);
								// System.out.printf("Received packet at %s cpalen=%-4d len=%-4d %s\n",new
								// Date(pcapPacket.getCaptureHeader().timestampInMillis()),pcapPacket.getCaptureHeader().caplen(),
								// pcapPacket.getCaptureHeader().wirelen(),s);
							}
						};
						// -1代表一直嗅探.
						pcap.loop(-1, pcapPacketHandler, "Jnetpcap rocks");
						// System.out.println(device.toString());
					});
					snifferThread.start();// 线程开始
				}
			}
		});
		// 保存文件操作
		fileSave.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				// TODO Auto-generated method stub
				int result = writeIntoFile(packets);
				if (result == 0) {
					Alert DevNotSelected = new Alert(Alert.AlertType.INFORMATION);
					// DevNotSelected.setTitle("网络设备无效");
					// DevNotSelected.setHeaderText("请选择一个网络设备！");
					DevNotSelected.setContentText("文件已保存至D:\\MyCapturePacket");
					DevNotSelected.show();
				} else {
					Alert DevNotSelected = new Alert(Alert.AlertType.INFORMATION);
					DevNotSelected.setContentText("文件保存失败");
					DevNotSelected.show();
				}
			}
		});
	}

	// 设置选择了过滤的行为
	public synchronized void flitterChanged() {
		System.out.println("update list.");
		packetsShow.clear();
		packetsShow.add(new PcapPacket(0));
		http = CtrlFlitter.isHttp();
		arp = CtrlFlitter.isArp();
		icmp = CtrlFlitter.isIcmp();
		tcp = CtrlFlitter.isTcp();
		udp = CtrlFlitter.isUdp();
		ip4 = CtrlFlitter.isIp4();
		ip6 = CtrlFlitter.isIp6();
		tcpN = 0;
		udpN = 0;
		totalN = 0;
		icmpN = 0;
		httpN = 0;
		ipv4N = 0;
		ipv6N = 0;
		arpN = 0;
		otherN = 0;
		if (packets.size() == 0) {
			return;
		}
		// 这里就相当于重新添加所有数据....这也是为什么选择过滤协议之后数据突然刷新的name快的原因
		for (PcapPacket item : packets) {
			if (http && item.hasHeader(new Http())) {
				httpN++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (icmp && item.hasHeader(new Icmp())) {
				icmpN++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (tcp && item.hasHeader(new Tcp())) {
				tcpN++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (udp && item.hasHeader(new Udp())) {
				udpN++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (ip4 && item.hasHeader(new Ip4())) {
				ipv4N++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (ip6 && item.hasHeader(new Ip6())) {
				ipv6N++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (arp && item.hasHeader(new Arp())) {
				arpN++;
				totalN++;
				packetsShow.add(item);
			}
		}
		// 刷新视图
		Platform.runLater(() -> {
			icmpPacket.setText("" + icmpN);
			arpPacket.setText("" + arpN);
			tcpPacket.setText("" + tcpN);
			udpPacket.setText("" + udpN);
			totalPacket.setText("" + totalN);
			httpPacket.setText(httpN + "");
			ipv4Packet.setText("" + ipv4N);
			ipv6Packet.setText(" " + ipv6N + " ");
			otherPacket.setText(totalN - tcpN - udpN - ipv4N - icmpN - ipv6N - arpN - httpN + "");
		});
	}

	class packetCell extends ListCell<PcapPacket> {
		@Override
		synchronized protected void updateItem(PcapPacket item, boolean empty) {
			super.updateItem(item, empty);
			Platform.runLater(() -> {
				setGraphic(null);
				setText(null);
				// System.out.println(packetsShow.indexOf(item));
				if (item != null && packetsShow.indexOf(item) == 0) {
					HBox hBox = new HBox();
					Text id = new Text("序号");
					id.setWrappingWidth(30);
					id.setTextAlignment(TextAlignment.CENTER);
					Text srcIP = new Text("源IP地址");
					srcIP.setWrappingWidth(95);
					srcIP.setTextAlignment(TextAlignment.CENTER);
					Text dstIP = new Text("目的IP地址");
					dstIP.setWrappingWidth(95);
					dstIP.setTextAlignment(TextAlignment.CENTER);
					Text srcMac = new Text("源MAC地址");
					srcMac.setWrappingWidth(110);
					srcMac.setTextAlignment(TextAlignment.CENTER);
					Text dstMac = new Text("目的MAC地址");
					dstMac.setWrappingWidth(110);
					dstMac.setTextAlignment(TextAlignment.CENTER);
					Text length = new Text("长度");
					length.setWrappingWidth(30);
					length.setTextAlignment(TextAlignment.CENTER);
					Text prot = new Text("协议");
					prot.setWrappingWidth(40);
					prot.setTextAlignment(TextAlignment.CENTER);
					Text time = new Text("时间");
					time.setWrappingWidth(80);
					time.setTextAlignment(TextAlignment.CENTER);
					hBox.getChildren().addAll(id, srcIP, dstIP, srcMac, dstMac, length, prot, time);
					setGraphic(hBox);
				} else {
					if (item != null) {
						// 将获取到的数据填充到listview里去
						Ethernet eth = new Ethernet();
						Ip4 ip4 = new Ip4();
						item.hasHeader(ip4);
						item.hasHeader(eth);
						HBox hBox = new HBox();
						// 获取当前的数目...
						Text id = new Text("" + packetsShow.indexOf(item));
						id.setWrappingWidth(30);
						id.setTextAlignment(TextAlignment.CENTER);
						// 获取数据包源地址
						Text srcIP;
						try {
							srcIP = new Text(FormatUtils.ip(ip4.source()));
						} catch (NullPointerException e) {
							srcIP = new Text("---.---.---.---");
						}
						srcIP.setWrappingWidth(95);
						srcIP.setTextAlignment(TextAlignment.CENTER);
						// 获取数据包目的地址
						Text dstIP;
						try {
							dstIP = new Text(FormatUtils.ip(ip4.destination()));
						} catch (NullPointerException e) {
							dstIP = new Text("---.---.---.---");
						}
						dstIP.setWrappingWidth(95);
						dstIP.setTextAlignment(TextAlignment.CENTER);
						// 获取数据报原mac地址
						Text srcMac = new Text(FormatUtils.mac(eth.source()));
						srcMac.setWrappingWidth(110);
						srcMac.setTextAlignment(TextAlignment.CENTER);
						// 获取数据包目的mac地址
						Text dstMac = new Text(FormatUtils.mac(eth.destination()));
						dstMac.setWrappingWidth(110);
						dstMac.setTextAlignment(TextAlignment.CENTER);
						// 获取数据包的长度
						Text length = new Text("" + item.getCaptureHeader().wirelen());
						length.setWrappingWidth(30);
						length.setTextAlignment(TextAlignment.CENTER);
						String protocol = null;
						// 判断协议的类型
						if (item.hasHeader(new Arp())) {
							protocol = "ARP";
						}
						if (item.hasHeader(new Ip4())) {
							protocol = "IPv4";
						} else if (item.hasHeader(new Ip6())) {
							protocol = "IPv6";
						}
						if (item.hasHeader(new Udp())) {
							protocol = "UDP";
						}
						if (item.hasHeader(new Tcp())) {
							protocol = "TCP";
						}
						if (item.hasHeader(new Icmp())) {
							protocol = "ICMP";
						}

						if (item.hasHeader(new Http())) {
							protocol = "HTTP";
						}
						Text prot = new Text(protocol);
						prot.setWrappingWidth(40);
						prot.setTextAlignment(TextAlignment.CENTER);
						// 将数据包的时间转换为我们熟悉的形式
						Text time = new Text(
								new SimpleDateFormat("HH:mm:ss").format(item.getCaptureHeader().timestampInMillis()));
						time.setWrappingWidth(80);
						time.setTextAlignment(TextAlignment.CENTER);
						// 将新添加的数据包生成的视图添加到ListView里去
						hBox.getChildren().addAll(id, srcIP, dstIP, srcMac, dstMac, length, prot, time);
						setGraphic(hBox);
					}
				}
			});
		}

	}

	public int writeIntoFile(ObservableList<PcapPacket> packets) {
		Date date = new Date();
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
		String nowTime = format.format(date);
		System.out.println(nowTime);
		// 先判断文件夹是否存在，不存在那么先创建文件夹
		File outPutDir = new File("D:\\MyCapturePacket");
		if (!outPutDir.exists()) {
			outPutDir.mkdirs();
		}
		nowTime = nowTime.replaceAll(":", ".");
		File outPutFile = new File("D:\\MyCapturePacket\\" + nowTime + ".txt");
		if (!outPutFile.exists()) {
			try {
				outPutFile.createNewFile();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		try {
			PrintWriter pw = new PrintWriter(outPutFile);
			List<DataPackageModel> list = new ArrayList<DataPackageModel>();
			int count = 0;
			// 将数据都添加到我们的model里去
			for (PcapPacket packet : packets) {
				Ethernet eth = new Ethernet();
				Ip4 ip4 = new Ip4();
				packet.hasHeader(ip4);
				packet.hasHeader(eth);
				// 讲数据填充到对象里去
				DataPackageModel model = new DataPackageModel();
				model.setId("" + (++count));
				String srcIp;
				String desIp;
				String protocol;
				try {
					srcIp = new String(FormatUtils.ip(ip4.source()));
				} catch (Exception e) {
					// TODO: handle exception
					srcIp = "---.---.---.---";
				}
				try {
					desIp = new String(FormatUtils.ip(ip4.destination()));
				} catch (Exception e) {
					// TODO: handle exception
					desIp = "---.---.---.---";
				}
				model.setSrcIp(srcIp);
				model.setDesIp(desIp);
				model.setSrcMac(new String(FormatUtils.mac(eth.source())));
				model.setDesMac(new String(FormatUtils.mac(eth.destination())));
				model.setLength(packet.getCaptureHeader().wirelen() + "");
				// 判断是什么协议
				model.setProtocol(judgePro(packet));
				model.setTime(new SimpleDateFormat("HH:mm:ss").format(packet.getCaptureHeader().timestampInMillis()));
				model.setContent(packet.toHexdump());
				list.add(model);
			}
			for (DataPackageModel model : list) {
				pw.print(model);
				pw.println();
				pw.println("--------------------------------");
				pw.println("--------------------------------");
				pw.println("--------------------------------");
			}
			pw.flush();
			pw.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public String judgePro(PcapPacket item) {
		String protocol = null;
		// 判断协议的类型
		if (item.hasHeader(new Arp())) {
			protocol = "ARP";
		}
		if (item.hasHeader(new Ip4())) {
			protocol = "IPv4";
		} else if (item.hasHeader(new Ip6())) {
			protocol = "IPv6";
		}
		if (item.hasHeader(new Udp())) {
			protocol = "UDP";
		}
		if (item.hasHeader(new Tcp())) {
			protocol = "TCP";
		}
		if (item.hasHeader(new Icmp())) {
			protocol = "ICMP";
		}

		if (item.hasHeader(new Http())) {
			protocol = "HTTP";
		}
		return protocol;
	}
}
