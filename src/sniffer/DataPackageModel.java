package sniffer;

public class DataPackageModel {

	private String id;
	private String srcIp;
	private String desIp;
	private String srcMac;
	private String desMac;
	private String length;
	private String protocol;
	private String time;
	private String content;

	/**
	 * @return the id
	 */
	public String getId() {
		return id;
	}

	/**
	 * @param id
	 *            the id to set
	 */
	public void setId(String id) {
		this.id = id;
	}

	/**
	 * @return the srcIp
	 */
	public String getSrcIp() {
		return srcIp;
	}

	/**
	 * @param srcIp
	 *            the srcIp to set
	 */
	public void setSrcIp(String srcIp) {
		this.srcIp = srcIp;
	}

	/**
	 * @return the desIp
	 */
	public String getDesIp() {
		return desIp;
	}

	/**
	 * @param desIp
	 *            the desIp to set
	 */
	public void setDesIp(String desIp) {
		this.desIp = desIp;
	}

	/**
	 * @return the srcMac
	 */
	public String getSrcMac() {
		return srcMac;
	}

	/**
	 * @param srcMac
	 *            the srcMac to set
	 */
	public void setSrcMac(String srcMac) {
		this.srcMac = srcMac;
	}

	/**
	 * @return the desMac
	 */
	public String getDesMac() {
		return desMac;
	}

	/**
	 * @param desMac
	 *            the desMac to set
	 */
	public void setDesMac(String desMac) {
		this.desMac = desMac;
	}

	/**
	 * @return the length
	 */
	public String getLength() {
		return length;
	}

	/**
	 * @param length
	 *            the length to set
	 */
	public void setLength(String length) {
		this.length = length;
	}

	/**
	 * @return the protocol
	 */
	public String getProtocol() {
		return protocol;
	}

	/**
	 * @param protocol
	 *            the protocol to set
	 */
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	/**
	 * @return the time
	 */
	public String getTime() {
		return time;
	}

	/**
	 * @param time
	 *            the time to set
	 */
	public void setTime(String time) {
		this.time = time;
	}

	/**
	 * @return the content
	 */
	public String getContent() {
		return content;
	}

	/**
	 * @param content
	 *            the content to set
	 */
	public void setContent(String content) {
		this.content = content;
	}

	public DataPackageModel() {
		super();
		// TODO Auto-generated constructor stub
	}

	@Override
	public String toString() {
		String[] contents = content.split("[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:");
		StringBuilder finalContent = new StringBuilder();
		for (String item : contents) {
			System.out.println(item);
			finalContent.append(item + "\r\n");
		}
		return "id=" + id + "\r\nsrcIp=" + srcIp + "\r\ndesIp=" + desIp + "\r\nsrcMac=" + srcMac + "\r\ndesMac="
				+ desMac + "\r\nlength=" + length + "\r\nprotocol=" + protocol + "\r\ntime=" + time + "\r\ncontent="
				+ finalContent.toString() + "";
	}

}
