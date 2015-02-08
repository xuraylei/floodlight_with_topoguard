package net.floodlightcontroller.topologysecurity;


import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.LLDP;
import net.floodlightcontroller.util.MACAddress;

class HostEntity{
	MACAddress mac;
	InetAddress ip;
	
	
	
	public HostEntity(MACAddress mac, InetAddress ip){
		this.mac = mac;
		this.ip = ip;
	}
}

class Port {
	Long sw;			//dpid of switch
	Short port_number;	

	public Port(Long dpid, Short port) {
		this.sw = dpid;
		this.port_number = port;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final Port other = (Port) obj;
		if (this.sw != other.sw) {
			return false;
		}
		if (this.port_number != other.port_number) {
			return false;
		}
		return true;
	}

	// naiive version of hash computation
	@Override
	public int hashCode() {
		int hash = 3;
		hash = 67 * hash + this.sw.hashCode();
		hash = 67 * hash + this.port_number;
		return hash;
	}
};

public class TopoloyUpdateChecker implements IDeviceListener,
		ILinkDiscoveryListener, IFloodlightModule {

	private static final HostEntity[] HostEntity = null;
	protected IFloodlightProviderService floodlightProvider;
	protected IDeviceService deviceService;
	protected ILinkDiscoveryService linkDiscoveryService;
	protected static Logger logger;

	// Implementation of PortManager
	protected PortManager portManager;
	
	protected HostProber hostProber;
	
	protected static String ControllerIP = "10.0.1.100";
		
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void deviceAdded(IDevice device) {
		logger.info("Device:{} is added on:", device.getMACAddressString());
		for (SwitchPort sp : device.getAttachmentPoints()) {
			logger.info("sw:{},port:{}", sp.getSwitchDPID(), sp.getPort());
		}

	}

	@Override
	public void deviceRemoved(IDevice device) {
		// TODO Auto-generated method stub
	}

	@Override
	public void deviceMoved(IDevice device) {
		// convert src mac address to MACAddress
		MACAddress src_mac = MACAddress.valueOf(device.getMACAddress());
		
		SwitchPort[] previousLocation = device.getOldAP();
		if (previousLocation.length == 1) { // only one location in AP history
			long previousDpid= previousLocation[0].getSwitchDPID();
			short previousPortID = (short) previousLocation[0].getPort();
			Port previousPort = new Port(previousDpid, previousPortID);

			Map<MACAddress, Boolean> hosts = this.portManager.port_list
					.get(previousPort).hosts;
			
			if (!hosts.containsKey(src_mac)){
				//logger.error("can not read previous host location about {}",src_mac);
				return;
			}
			if (hosts.get(src_mac) == false) { // indicating the host is not disabled	 
				//Violation: no port shutdown signal is received during host move
				logger.warn("Violation: Host Move from switch {} port {} without Port ShutDown"
						, previousDpid, previousPortID);
			} 
			//host prober to send ARP Ping to testify the liveness of host
			InetAddress src_ip;
			try {
				if (device.getIPv4Addresses().length < 1){
					return;
				}
				src_ip = InetAddress.getByAddress(BigInteger.valueOf(device.getIPv4Addresses()[0]).toByteArray());
				if (hostProber.sendHostProbe(src_ip, src_mac, previousDpid, previousPortID)){
					List<HostEntity> hostEntity = hostProber.probedPorts.get(previousPort);
					if (hostEntity == null){
						hostEntity = new ArrayList<HostEntity>();
					}
					hostEntity.add(new HostEntity(src_mac, src_ip));
					hostProber.probedPorts.put(previousPort, hostEntity);
				}			
			} catch (UnknownHostException e) {
				logger.error("Can not convert string to InetAddress,{}",e.getMessage());
			}
				
			
		}
	}
	
	@Override
	public void deviceIPV4AddrChanged(IDevice device) {
		// TODO Auto-generated method stub

	}

	@Override
	public void deviceVlanChanged(IDevice device) {
		// TODO Auto-generated method stub

	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);

		l.add(ILinkDiscoveryService.class);
		l.add(IDeviceService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		deviceService = context.getServiceImpl(IDeviceService.class);
		linkDiscoveryService = context
				.getServiceImpl(ILinkDiscoveryService.class);

		logger = (Logger) LoggerFactory.getLogger(PortManager.class);

		portManager = new PortManager();
		hostProber = new HostProber();

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {

		deviceService.addListener(this);
		linkDiscoveryService.addListener(this);

		// Register for the OpenFlow messages we want to receive for PortManager
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN,
				this.portManager);

		// Register for switch updates for PortManager
		floodlightProvider.addOFSwitchListener(this.portManager);

	}

	/*
	 * check link update
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) {
	//	logger.error("receive single link update");

	}

	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) {
	//	logger.error("receive boundle link update");

	}

	class PortManager implements IOFMessageListener, IOFSwitchListener {

		protected Map<Port, PortProperty> port_list; // the port list to keep
														// port property
		protected Map<MACAddress, Port> mac_port; // for quick locate host
													// location

		public PortManager() {
			port_list = new HashMap<Port, PortProperty>();
			mac_port = new HashMap<MACAddress, Port>();
		}

		@Override
		public String getName() {
			return "Port Manager";
		}

		@Override
		public boolean isCallbackOrderingPrereq(OFType type, String name) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean isCallbackOrderingPostreq(OFType type, String name) {
			// in case other modules eat Packet-In message
			return (type.equals(OFType.PACKET_IN) && (name.equals("topology")
					|| name.equals("linkdiscovery") || name
						.equals("devicemanager")));
		}

		@Override
		public Command receive(IOFSwitch sw, OFMessage msg,
				FloodlightContext cntx) {
			switch (msg.getType()) {
			
			case PACKET_IN:
				return this.processPacketInMessage(sw, (OFPacketIn) msg, cntx);
			default:
				break;
			}

			return Command.CONTINUE;
		}

		// ******************
		// IOFSwitchListener
		// ******************
		@Override
		public void switchAdded(long switchId) {
			this.handleSwitchAdd(switchId);
		}

		@Override
		public void switchRemoved(long switchId) {
			// TODO delete corresponding ports?

		}

		@Override
		public void switchActivated(long switchId) {
			// do nothing

		}

		@Override
		public void switchPortChanged(long switchId, ImmutablePort port,
				PortChangeType type) {
			switch (type) {
			case DELETE:
			case DOWN:
				this.handlePortDown(switchId, port);
				break;
			default:
				break;
			}

		}

		@Override
		public void switchChanged(long switchId) {
			// do nothing

		}

		// ******************
		// Message Handler
		// ******************

		/*
* 
*/
		void handleSwitchAdd(long dpid) {
			IOFSwitch sw = floodlightProvider.getSwitch(dpid);
			for (ImmutablePort port : sw.getPorts()) {
				Port switch_port = new Port(dpid, port.getPortNumber());
				if (!this.port_list.containsKey(switch_port)) {
					this.port_list.put(switch_port, new PortProperty());
				}

			}
		}
		

		/*
		 * we disable all attached hosts if the port  shut down
		 */
		void handlePortDown(long dpid, ImmutablePort port) {
			Port switch_port = new Port(dpid, port.getPortNumber());			
			PortProperty pp = this.port_list.get(switch_port);
			pp.receivePortDown();
			this.port_list.put(switch_port, pp);
		}

		
		Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi,
				FloodlightContext cntx) {
			Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
					IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			long dpid = sw.getId();
			short inport = pi.getInPort();
			Port switch_port = new Port(dpid, inport);
			MACAddress src_mac = eth.getSourceMAC();

			PortProperty pp = this.port_list.get(switch_port);
			if (pp == null)
				return Command.CONTINUE;
			DeviceType dt = pp.getDeviceType();

			// testify if the packet is the response to Host Probing
			if (eth.isBroadcast())
				return Command.CONTINUE;
		
				try {
					if (eth.getEtherType() == Ethernet.TYPE_IPv4){
						IPv4 ip = (IPv4) eth.getPayload();
						InetAddress srcIP = InetAddress.getByAddress(
								BigInteger.valueOf(ip.getSourceAddress()).toByteArray());
						InetAddress dstIP = InetAddress.getByAddress(
								BigInteger.valueOf(ip.getDestinationAddress()).toByteArray());
						if(ip.getProtocol() == IPv4.PROTOCOL_ICMP){
							ICMP icmp = (ICMP) ip.getPayload();
							if (icmp.getIcmpCode() == ICMP.ECHO_REPLY){
								if (hostProber.probedPorts.containsKey(switch_port)){
									for (HostEntity he : hostProber.probedPorts.get(switch_port)){
										if (he.ip.equals(srcIP) && he.mac.equals(eth.getSourceMAC())  &&
												InetAddress.getByName(ControllerIP).equals(dstIP)){
											//we think this is the response to host probing
											//Violation: host is still reachable at previous locaiton
											logger.warn("Violation: Host Move from switch {} port {} is still reachable"
													, dpid, inport);
											List<HostEntity> hostEntity = hostProber.probedPorts.get(switch_port);
											hostEntity.remove(he);
											hostProber.probedPorts.put(switch_port, hostEntity);
											return Command.STOP;
										}
									}
								}
							}
						}
					}
				} catch (UnknownHostException e) {
					logger.error("Cannot construct InetAddress, {}", e.getMessage());
				}
				

			// if the payload is lldp, we do not verify correctness of LLDP in this point
			if (eth.getPayload() instanceof LLDP) {
				if (dt == DeviceType.ANY) {
					pp.setPortSwitch();
				} else if (dt == DeviceType.HOST) {
					// Violation: impossible to receive LLDP from HOST port, Countermeasure: eat the lldp
					logger.warn("Violation: Receive LLDP packets from HOST port: SW {} port {}"
							, dpid, inport);
					return Command.STOP;
				}
			}
			// if the payload is host traffic
			else {
				// if this host found before
				if (this.mac_port.containsKey(src_mac)) { 
					Port host_location = this.mac_port.get(src_mac);
					if (host_location == switch_port) {
						// this port is first hop port for found host
						if (dt == DeviceType.SWITCH) {
							// Violation:  receive first hop traffic from SWITH port
							logger.warn("Violation: Receive first hop host packets from SWITCH port: SW {} port {}"
									, dpid, inport);
							//return Command.STOP;
						} else if (dt == DeviceType.ANY) {
							//this happened if the port is shutdown
							pp.setPortHost();
							pp.disableHostShutDown(src_mac);
							this.port_list.put(switch_port, pp);
						}
					}
				} 
				else { // new host
					this.mac_port.put(src_mac, switch_port);

					pp.addHost(src_mac);	
					pp.setPortAny();
					this.port_list.put(switch_port, pp);
	

				}
				
			}
			return Command.CONTINUE;
		}
		
	}

	
	class HostProber{
		MACAddress senderMAC;
		MACAddress targetMAC;
		MACAddress broadcastMAC;
		MACAddress emptyMAC;
		InetAddress senderIP;
		InetAddress targetIP;
		
		//we use Port as key, since it is not common that one host entity attach to multiple ports
		Map<Port, List<HostEntity>> probedPorts;
		
		public HostProber(){
			senderMAC = MACAddress.valueOf("aa:aa:aa:aa:aa:aa");
			broadcastMAC = MACAddress.valueOf("ff:ff:ff:ff:ff:ff");
			emptyMAC = MACAddress.valueOf("00:00:00:00:00:00");
			probedPorts = new HashMap<Port, List<HostEntity>>();
			
			try {
				senderIP = InetAddress.getByName(ControllerIP);
			} catch (UnknownHostException e) {
				logger.error("Cannot construct InetAddress, {}", e.getMessage());
			}
		}
		
		
		protected boolean sendHostProbe(InetAddress ip, MACAddress mac, long dpid, short port){
			byte[] data;
			
			//Currently, we use ICMPing to probe the host
			// data = generateARPPing(ip);
			data = generateICMPPing(ip, mac);
			
			IOFSwitch sw = floodlightProvider.getSwitch(dpid);
			
	        if (sw == null) {
	            return false;
	        }
	        ImmutablePort ofpPort = sw.getPort(port);

	        if (ofpPort == null) {
	            if (logger.isTraceEnabled()) {
	                logger.trace("Null physical port. sw={}, port={}", sw, port);
	            }
	            return false;
	        }

	        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory().getMessage(OFType.PACKET_OUT);
	        po.setBufferId(OFPacketOut.BUFFER_ID_NONE);
	        po.setInPort(OFPort.OFPP_NONE);

	        // set actions
	        List<OFAction> actions = new ArrayList<OFAction>();
	        actions.add(new OFActionOutput(port, (short) 0));
	        po.setActions(actions);
	        po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

	        // set data
	        po.setLengthU(OFPacketOut.MINIMUM_LENGTH + po.getActionsLength() + data.length);
	        po.setPacketData(data);

	        // send
	        try {
	            sw.write(po, null);
	            sw.flush();
	        } catch (IOException e) {
	            logger.error("Failure sending host probe out port {} on switch {}",
	                      new Object[]{ port, sw.getStringId() }, e);
	            return false;
	        }
	        return true;
	        
		}
		
		protected byte[] generateICMPPing(InetAddress ip, MACAddress mac){
			targetIP = ip;
			targetMAC = mac;
			IPacket packet = new IPv4()
            .setProtocol(IPv4.PROTOCOL_ICMP)
            .setSourceAddress(ControllerIP)
            .setDestinationAddress(ip.hashCode())  //this is tricky
            .setPayload(new ICMP()
                            .setIcmpType((byte) 8)
                            .setIcmpCode((byte) 0)
                            .setPayload(new Data(new byte[]
                                        {0x76, (byte) 0xf2, 0x0, 0x2, 0x1, 0x1, 0x1}))
                       );
	        Ethernet ethernet = new Ethernet().setSourceMACAddress(senderMAC.toBytes())
	        						 .setDestinationMACAddress(targetMAC.toBytes())
	        						 .setEtherType(Ethernet.TYPE_IPv4);
	        
	        ethernet.setPayload(packet);
	        
	        return ethernet.serialize();
		}
		
		protected byte[] generateARPPing(InetAddress ip, MACAddress mac){
			targetIP = ip;
			ARP arp = new ARP().setHardwareType(ARP.HW_TYPE_ETHERNET)
	        			   .setProtocolType(ARP.PROTO_TYPE_IP)
	        			   .setHardwareAddressLength((byte) 6)
	        			   .setProtocolAddressLength((byte) 4)
	        			   .setOpCode(ARP.OP_RARP_REQUEST)
	        			   .setSenderHardwareAddress(senderMAC.toBytes())
	        			   .setSenderProtocolAddress(senderIP.getAddress())
	        			   .setTargetHardwareAddress(emptyMAC.toBytes())
	        			   .setTargetProtocolAddress(targetIP.getAddress());
	        Ethernet ethernet = new Ethernet().setSourceMACAddress(senderMAC.toBytes())
	        						 .setDestinationMACAddress(broadcastMAC.toBytes())
	        						 .setEtherType(Ethernet.TYPE_ARP);
	        
	        ethernet.setPayload(arp);
	        
	        return ethernet.serialize();
	       
	        
		}
	}
	
}