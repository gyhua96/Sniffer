package sniffer;

import org.jnetpcap.PcapIf;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

	@Override
	public void start(Stage primaryStage) throws Exception {
		PcapIf device = null;
		// Parent root = FXMLLoader.load(getClass().getResource("main.fxml"));
		// 下面是加载两个布局到对象里，之后再调用这个FXMLLoader对象的load()方法,就可以返回一个Parent对象
		// 通过Scene的一个使用Parent构造方法,我们可以生产这个对应xml视图的scene对象
		FXMLLoader fxmlLoaderInterface = new FXMLLoader(getClass().getResource("interface.fxml"));
		FXMLLoader fxmlLoaderMain = new FXMLLoader(getClass().getResource("Main.fxml"));
		Parent interfaces = fxmlLoaderInterface.load();
		Parent main = fxmlLoaderMain.load();
		ControllerInterface CtrlInterf = fxmlLoaderInterface.getController();
		// 有点懵逼,,这里不就是把一个空指针的值给赋给了CtrlInterf这个引用么...
		// 不是空指针，这里是获得fxml文件里指定的控制器，然后我们就可以使用这个fxml的控制器了
		device = CtrlInterf.getInterface();

		primaryStage.setTitle("Sniffer");
		// primaryStage.setScene(new Scene(interfaces));
		primaryStage.setScene(new Scene(main)); // 加载main布局到stage里去
		primaryStage.show();
	}

	public static void main(String[] args) {
		launch(args);
	}
}
