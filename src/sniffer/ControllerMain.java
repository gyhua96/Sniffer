package sniffer;

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
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;
import javafx.scene.text.TextAlignment;
import javafx.stage.Stage;
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
import java.io.IOException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ResourceBundle;

public class ControllerMain implements Initializable {
    @FXML
    private MenuBar menuBar;
    @FXML
    private MenuItem selectInterface;
    @FXML
    private MenuItem startSniffer;
    @FXML
    private MenuItem flitters;
    @FXML
    private ListView<PcapPacket> listPackets;
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
    ControllerInterface CtrlInterf;
    ControllerFlitter CtrlFlitter;
    Stage stage = null;
    StringBuilder errbuf = new StringBuilder();
    Thread snifferThread = null;
    private PcapIf device = null;
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
        fxmlLoaderInterface = new FXMLLoader(getClass().getResource("interface.fxml"));
        fxmlLoaderFlitter = new FXMLLoader(getClass().getResource("flitter.fxml"));
        CtrlInterf = fxmlLoaderInterface.getController();

        Parent interfaces = null;
        try {
            interfaces = fxmlLoaderInterface.load();
        } catch (IOException e) {
            e.printStackTrace();
        }
        final Stage stageInterface = new Stage();
        stageInterface.setScene(new Scene(interfaces));
        stageInterface.setTitle("选择网络设备");
        Parent flitter = null;
        try {
            flitter = fxmlLoaderFlitter.load();
        } catch (IOException e) {
            e.printStackTrace();
        }
        final Stage stageFlitter = new Stage();
        stageFlitter.setScene(new Scene(flitter));
        stageFlitter.setTitle("选择筛选协议");
        CtrlFlitter = fxmlLoaderFlitter.getController();
        CtrlFlitter.setMainController(this);
        packets.addListener((ListChangeListener<PcapPacket>) c -> {
            PcapPacket item = packets.get(packets.size() - 1);
            Platform.runLater(new Runnable() {
                @Override
                public void run() {
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
                if (http && item.hasHeader(new Http())) {
                    totalN++;
                    httpN++;
                    packetsShow.add(item);
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
            }

        });
        listPackets.setItems(packetsShow);
        listPackets.setCellFactory((ListView<PcapPacket> item) -> new packetCell());
        listPackets.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<PcapPacket>() {
            @Override
            public void changed(ObservableValue<? extends PcapPacket> observable, PcapPacket oldValue, PcapPacket newValue) {
                if (packetsShow.indexOf(newValue) == 0) {
                    return;
                }
                dataDump.setText(newValue.toHexdump());
            }
        });
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
        stopSniffer.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {

                if (snifferThread != null) {
                    snifferThread.stop();
                    snifferThread = null;
                    //System.out.println("stop sniffer");
                }
            }
        });
        startSniffer.setOnAction(new EventHandler<javafx.event.ActionEvent>() {
            @Override
            public void handle(javafx.event.ActionEvent event) {

                CtrlInterf = fxmlLoaderInterface.getController();
                if (CtrlInterf == null || CtrlInterf.getInterface() == null) {
                    Alert DevNotSelected = new Alert(Alert.AlertType.WARNING);
                    DevNotSelected.setTitle("网络设备无效");
                    DevNotSelected.setHeaderText("请选择一个网络设备！");
                    DevNotSelected.setContentText("未选择网络设备或网络设备无效！");
                    DevNotSelected.show();
                } else {
                    snifferThread = new Thread(() -> {
                        device = CtrlInterf.getInterface();
                        int snaplen = 64 * 1024;
                        int flags = Pcap.MODE_PROMISCUOUS;
                        int timeout = 3 * 1000;
                        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
                        if (pcap == null) {
                            System.out.println("Error while opening device for capture." + errbuf);
                        }
                        PcapPacketHandler<String> pcapPacketHandler = new PcapPacketHandler<String>() {
                            @Override
                            public void nextPacket(PcapPacket pcapPacket, String s) {
                                if (pcapPacket.hasHeader(new Ip4()) || pcapPacket.hasHeader(new Arp())) {
                                    packets.add(pcapPacket);
                                }
                                //System.out.printf("Received packet at %s cpalen=%-4d len=%-4d %s\n",new Date(pcapPacket.getCaptureHeader().timestampInMillis()),pcapPacket.getCaptureHeader().caplen(), pcapPacket.getCaptureHeader().wirelen(),s);
                            }
                        };
                        pcap.loop(-1, pcapPacketHandler, "Jnetpcap rocks");
                        //System.out.println(device.toString());
                    });
                    snifferThread.start();
                }
            }
        });
    }


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
                //System.out.println(packetsShow.indexOf(item));
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
                        Ethernet eth = new Ethernet();
                        Ip4 ip4 = new Ip4();
                        item.hasHeader(ip4);
                        item.hasHeader(eth);
                        HBox hBox = new HBox();
                        Text id = new Text("" + packetsShow.indexOf(item));
                        id.setWrappingWidth(30);
                        id.setTextAlignment(TextAlignment.CENTER);
                        Text srcIP;
                        try {
                            srcIP = new Text(FormatUtils.ip(ip4.source()));
                        } catch (NullPointerException e) {
                            srcIP = new Text("---.---.---.---");
                        }
                        srcIP.setWrappingWidth(95);
                        srcIP.setTextAlignment(TextAlignment.CENTER);
                        Text dstIP;
                        try {
                            dstIP = new Text(FormatUtils.ip(ip4.destination()));
                        } catch (NullPointerException e) {
                            dstIP = new Text("---.---.---.---");
                        }
                        dstIP.setWrappingWidth(95);
                        dstIP.setTextAlignment(TextAlignment.CENTER);
                        Text srcMac = new Text(FormatUtils.mac(eth.source()));
                        srcMac.setWrappingWidth(110);
                        srcMac.setTextAlignment(TextAlignment.CENTER);
                        Text dstMac = new Text(FormatUtils.mac(eth.destination()));
                        dstMac.setWrappingWidth(110);
                        dstMac.setTextAlignment(TextAlignment.CENTER);
                        Text length = new Text("" + item.getCaptureHeader().wirelen());
                        length.setWrappingWidth(30);
                        length.setTextAlignment(TextAlignment.CENTER);
                        String protocol = null;
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
                        Text time = new Text(new SimpleDateFormat("HH:mm:ss").format(item.getCaptureHeader().timestampInMillis()));
                        time.setWrappingWidth(80);
                        time.setTextAlignment(TextAlignment.CENTER);
                        hBox.getChildren().addAll(id, srcIP, dstIP, srcMac, dstMac, length, prot, time);
                        setGraphic(hBox);
                    }
                }
            });
        }
    }
}


