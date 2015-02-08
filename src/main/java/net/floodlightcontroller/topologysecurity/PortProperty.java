package net.floodlightcontroller.topologysecurity;
import java.util.*;
import net.floodlightcontroller.util.MACAddress;

enum DeviceType{
	SWITCH, HOST, ANY
}

public class PortProperty {
	
	 DeviceType device_type;  // this identify the type of device
	 Map<MACAddress,Boolean> hosts; //host list of this port, including mac address and disable flag
	
	public PortProperty ()
	{
		this.device_type = DeviceType.ANY;
		hosts = new HashMap<MACAddress, Boolean>();
	}
	
	protected DeviceType getDeviceType()
	{
		return this.device_type;
	}
	
	protected void setPortHost()
	{
		this.device_type = DeviceType.HOST;
	}
	
	protected void setPortSwitch()
	{
		this.device_type = DeviceType.SWITCH;
	}
	
	protected void setPortAny()
	{
		this.device_type = DeviceType.ANY;
	}
	
	protected void addHost(MACAddress mac)
	{
		this.hosts.put(mac, false);
	}
	
	
	protected void receivePortShutDown()
	{
		this.hosts.clear();
		setPortAny();
		
	}
	
	protected void enableHostShutDown(MACAddress mac){
		this.hosts.put(mac, true);
	}
	
	protected void disableHostShutDown(MACAddress mac){
		this.hosts.put(mac, false);
	}
	
	protected void receivePortDown(){
		for (MACAddress mac : this.hosts.keySet()){
			this.hosts.put(mac, true);
		}
	}
	
	protected void receiveTrafficFromPort(boolean isLLDP, MACAddress src)
	{
		//receivePortUp();
		if(isLLDP)
			setPortSwitch();
		else
		{
			setPortHost();
			if(!hosts.containsKey(src))
				hosts.put(src,false);
		}
			
	}

}
