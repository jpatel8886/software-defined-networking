package edu.wisc.cs.sdn.apps.loadbalancer;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.ArpServer;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.util.MACAddress;

// Student imports
import java.util.List;

import java.nio.ByteBuffer;

import org.openflow.protocol.OFOXMField;

import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

import edu.wisc.cs.sdn.apps.l3routing.L3Routing;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
       IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();

	private static final byte TCP_FLAG_SYN = 0x02;

	private static final short IDLE_TIMEOUT = 20;

	// Interface to the logging system
	private static Logger log = LoggerFactory.getLogger(MODULE_NAME);

	// Interface to Floodlight core for interacting with connected switches
	private IFloodlightProviderService floodlightProv;

	// Interface to device manager service
	private IDeviceService deviceProv;

	// Switch table in which rules should be installed
	private byte table;

	private byte l3RoutingTable;

	// Set of virtual IPs and the load balancer instances they correspond with
	private Map<Integer,LoadBalancerInstance> instances;

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Loads dependencies and initializes data structures.
	 */
	@Override
		public void init(FloodlightModuleContext context)
		throws FloodlightModuleException 
		{
			log.info(String.format("Initializing %s...", MODULE_NAME));

			// Obtain table number from config
			Map<String,String> config = context.getConfigParams(this);
			this.table = Byte.parseByte(config.get("table"));

			// Create instances from config
			this.instances = new HashMap<Integer,LoadBalancerInstance>();
			String[] instanceConfigs = config.get("instances").split(";");
			for (String instanceConfig : instanceConfigs)
			{
				String[] configItems = instanceConfig.split(" ");
				if (configItems.length != 3)
				{ 
					log.error("Ignoring bad instance config: " + instanceConfig);
					continue;
				}
				LoadBalancerInstance instance = new LoadBalancerInstance(
						configItems[0], configItems[1], configItems[2].split(","));
				this.instances.put(instance.getVirtualIP(), instance);
				log.info("Added load balancer instance: " + instance);
			}

			this.floodlightProv = context.getServiceImpl(
					IFloodlightProviderService.class);
			this.deviceProv = context.getServiceImpl(IDeviceService.class);

			/*********************************************************************/
			/* TODO: Initialize other class variables, if necessary              */
			l3RoutingTable = L3Routing.table;

			/*********************************************************************/
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Subscribes to events and performs other startup tasks.
	 */
	@Override
		public void startUp(FloodlightModuleContext context)
		throws FloodlightModuleException 
		{
			log.info(String.format("Starting %s...", MODULE_NAME));
			this.floodlightProv.addOFSwitchListener(this);
			this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);

			/*********************************************************************/
			/* TODO: Perform other tasks, if necessary                           */

			/*********************************************************************/
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when a switch joins the network.
	 * @param DPID for the switch
	 */
	@Override
		public void switchAdded(long switchId) 
		{
			IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
			log.info(String.format("Switch s%d added", switchId));

			/*********************************************************************/
			/* TODO: Install rules to send:                                      */
			/*       (1) packets from new connections to each virtual load       */
			/*       balancer IP to the controller                               */
			/*       (2) ARP packets to the controller, and                      */
			/*       (3) all other packets to the next rule table in the switch  */

			installForwardingRules(sw);

			/*********************************************************************/
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
		public net.floodlightcontroller.core.IListener.Command receive(
				IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
		{
			// We're only interested in packet-in messages
			if (msg.getType() != OFType.PACKET_IN)
			{ return Command.CONTINUE; }
			OFPacketIn pktIn = (OFPacketIn)msg;

			// Handle the packet
			Ethernet ethPkt = new Ethernet();
			ethPkt.deserialize(pktIn.getPacketData(), 0, pktIn.getPacketData().length);

			/*********************************************************************/
			/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
			/*       SYNs sent to a virtual IP, select a host and install        */
			/*       connection-specific rules to rewrite IP and MAC addresses;  */
			/*       ignore all other packets                                    */
	
			// If packet is ARP Request, send ARP Response
			if (ethPkt.getEtherType() == Ethernet.TYPE_ARP)
			{
				ARP arpPacket = (ARP) ethPkt.getPayload();
				if (arpPacket.getOpCode() == ARP.OP_REQUEST) {
					boolean arpResponseSuccess = sendArpResponse(ethPkt, sw, pktIn.getInPort());
					if (arpResponseSuccess) return Command.STOP;
				}
			}

			// If packet is TCP request, process the request
			else if (ethPkt.getEtherType() == Ethernet.TYPE_IPv4)
			{	
				IPv4 ipPacket = (IPv4)ethPkt.getPayload();

				if (ipPacket.getProtocol() == IPv4.PROTOCOL_TCP)
				{
					TCP tcp = (TCP)ipPacket.getPayload();
					
					if (tcp.getFlags() == LoadBalancer.TCP_FLAG_SYN) {	
						System.out.println("\nReceived a TCP request, processing it");
						processTcpRequest(ethPkt, sw);
					}
				}
			}		

			/*********************************************************************/

			// We don't care about other packets
			return Command.CONTINUE;
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Install  virtual IPs, ARP, and default forwarding rules for newly added switch 'sw'  
	 */

	private void installForwardingRules (IOFSwitch sw)
	{
		// set forwarding rules for all virtual IPs 
		for (Integer vIP : instances.keySet()) {

			OFMatch vipMatchCriteria = new OFMatch();
			vipMatchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
			vipMatchCriteria.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
			vipMatchCriteria.setNetworkDestination(vIP);

			OFActionOutput controllerActionOutput = new OFActionOutput();
			controllerActionOutput.setPort(OFPort.OFPP_CONTROLLER);

			List<OFAction> vipListOfActions = new ArrayList<OFAction>();
			vipListOfActions.add(controllerActionOutput);

			OFInstructionApplyActions vipApplyActionsController = new OFInstructionApplyActions(vipListOfActions);

			List<OFInstruction> vipListOfInstructions = new ArrayList<OFInstruction>();
			vipListOfInstructions.add(vipApplyActionsController);

			// install rule for Virtual IP
			SwitchCommands.installRule(sw, table, (short)(SwitchCommands.DEFAULT_PRIORITY + (short)1), 
					vipMatchCriteria, vipListOfInstructions);
		}

		// ------------------------------------------------------------------------------------------

		// for ARP and Default rule
		OFMatch arpMatchCriteria = new OFMatch();
		OFMatch defaultMatchCriteria = new OFMatch();

		arpMatchCriteria.setDataLayerType(OFMatch.ETH_TYPE_ARP);

		OFActionOutput controllerActionOutput = new OFActionOutput();
		controllerActionOutput.setPort(OFPort.OFPP_CONTROLLER);

		OFInstructionGotoTable goToTableInstruction = new OFInstructionGotoTable(this.l3RoutingTable);

		List<OFAction> arpListOfActions = new ArrayList<OFAction>();
		List<OFInstruction> defaultListOfInstructions = new ArrayList<OFInstruction>();

		arpListOfActions.add(controllerActionOutput);
		defaultListOfInstructions.add(goToTableInstruction);

		OFInstructionApplyActions arpApplyActionsController = new OFInstructionApplyActions(arpListOfActions);

		List<OFInstruction> ArplistOfInstructions = new ArrayList<OFInstruction>();
		ArplistOfInstructions.add(arpApplyActionsController);

		// install rule for ARP
		SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, defaultMatchCriteria, defaultListOfInstructions);
		// install rule for default
		SwitchCommands.installRule(sw, table, (short)(SwitchCommands.DEFAULT_PRIORITY + (short)1), arpMatchCriteria, ArplistOfInstructions);

		return;
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	private boolean sendArpResponse (Ethernet ethPacket, IOFSwitch sw, int outPort)
	{
		MACAddress senderMAC = ethPacket.getSourceMAC();

		ARP arpPacket = (ARP) ethPacket.getPayload();
		int destIP = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
		int srcIP = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();

		if(!instances.containsKey((Integer)destIP))
		{
			System.err.println("Destination IP for the ARP Request --> Instance for dest IP not found");
			return false;
		}

		// get the LB Instance where this ARP request is received
		LoadBalancerInstance lbInstance = instances.get((Integer)destIP);
		byte[] lbMAC = lbInstance.getVirtualMAC();

		// Construct ethernet response packet
		Ethernet ethResponse = new Ethernet();
		ethResponse.setEtherType(Ethernet.TYPE_ARP);
		ethResponse.setSourceMACAddress(lbMAC);
		ethResponse.setDestinationMACAddress(senderMAC.toBytes());

		// construct ARP response header
		ARP arpResponse = new ARP();
		arpResponse.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arpResponse.setProtocolType(ARP.PROTO_TYPE_IP);
		arpResponse.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		arpResponse.setProtocolAddressLength((byte) 4);
		arpResponse.setOpCode(ARP.OP_REPLY);
		arpResponse.setSenderProtocolAddress(destIP);
		arpResponse.setSenderHardwareAddress(lbMAC);
		arpResponse.setTargetProtocolAddress(srcIP);
		arpResponse.setTargetHardwareAddress(senderMAC.toBytes());

		ethResponse.setPayload(arpResponse);

		// send the ARP response packet
		boolean sentSuccess = SwitchCommands.sendPacket(sw, (short)outPort, ethResponse);

		if (!sentSuccess)
		{
			System.err.println("Failed to send ARP response, for sender: " + srcIP);
			return false;
		
		}

		return true;
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	private void processTcpRequest (Ethernet packetIn, IOFSwitch sw)
	{
		IPv4 incomingIpv4 = (IPv4) packetIn.getPayload();
		TCP incomingTCP = (TCP) incomingIpv4.getPayload();
		
		int inPacketSrcIP = incomingIpv4.getSourceAddress();
		int inPacketDstIP = incomingIpv4.getDestinationAddress();
		short inPacketSrcPort = incomingTCP.getSourcePort();
		short inPacketDstPort = incomingTCP.getDestinationPort();

		// Try getting a host IP from LB Instances using the Virtual IP
		if (!instances.containsKey((Integer)inPacketDstIP))
		{
			System.err.println("Switch cannot find Loadbalancer instance for this packet's destIP");
			return;
		}

		int virtualIp = inPacketDstIP;

		LoadBalancerInstance lbInstance = instances.get((Integer) virtualIp);
		int assignedHostIP = lbInstance.getNextHostIP();
		byte[] virtualMAC = lbInstance.getVirtualMAC();
		byte[] assignedHostMAC = this.getHostMACAddress(assignedHostIP);

		//-----------------------------------------------------------------------------------------------------------//

		// Create connection-specific match rules for a new CLIENT -> SERVER connection 
		OFMatch clientToServerMatch = new OFMatch();
		clientToServerMatch.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		clientToServerMatch.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
		clientToServerMatch.setNetworkSource(inPacketSrcIP);
		clientToServerMatch.setNetworkDestination(virtualIp);
		clientToServerMatch.setTransportSource(inPacketSrcPort);
		clientToServerMatch.setTransportDestination(inPacketDstPort);

		// Create actions to rewrite IP & MAC for CLIENT -> SERVER connection
		OFActionSetField clientToServerMacChange = new OFActionSetField();
		clientToServerMacChange.setField(new OFOXMField(OFOXMFieldType.ETH_DST, assignedHostMAC));

		OFActionSetField clientToServerIpChange = new OFActionSetField();
		clientToServerIpChange.setField(new OFOXMField(OFOXMFieldType.IPV4_DST, (Integer) assignedHostIP));

		List<OFAction> clientToServerlistOfActions = new ArrayList<OFAction>();
		clientToServerlistOfActions.add(clientToServerMacChange);
		clientToServerlistOfActions.add(clientToServerIpChange);

		OFInstructionApplyActions applyActionsClientToServer = new OFInstructionApplyActions(clientToServerlistOfActions);
		OFInstructionGotoTable clientToServerGoTo = new OFInstructionGotoTable(this.l3RoutingTable);

		List<OFInstruction> clientToServerInstructionsList = new ArrayList<OFInstruction>();
		clientToServerInstructionsList.add(applyActionsClientToServer);
		clientToServerInstructionsList.add(clientToServerGoTo);

		// Install Rules for CLIENT -> SERVER connection
		SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + (short) 2),
				clientToServerMatch, clientToServerInstructionsList, (short) 0, (short)20);

		//-----------------------------------------------------------------------------------------------------------//

		// Create connection-specific match rules for a new SERVER -> CLIENT connection 
		OFMatch serverToClientMatch = new OFMatch();
		serverToClientMatch.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		serverToClientMatch.setNetworkProtocol(OFMatch.IP_PROTO_TCP);
		serverToClientMatch.setNetworkSource(assignedHostIP);
		serverToClientMatch.setNetworkDestination(inPacketSrcIP);
		serverToClientMatch.setTransportSource(inPacketDstPort);
		serverToClientMatch.setTransportDestination(inPacketSrcPort);

		// Create actions to rewrite IP & MAC for SERVER -> CLIENT connection
		OFActionSetField serverToClientMacChange = new OFActionSetField();
		serverToClientMacChange.setField(new OFOXMField(OFOXMFieldType.ETH_SRC, virtualMAC));

		OFActionSetField serverToClientIpChange = new OFActionSetField();
		serverToClientIpChange.setField(new OFOXMField(OFOXMFieldType.IPV4_SRC, (Integer) virtualIp));

		List<OFAction> serverToClientlistOfActions = new ArrayList<OFAction>();
		serverToClientlistOfActions.add(serverToClientMacChange);
		serverToClientlistOfActions.add(serverToClientIpChange);

		OFInstructionApplyActions applyActionsServerToClient = new OFInstructionApplyActions(serverToClientlistOfActions);
		OFInstructionGotoTable serverToClientGoto = new OFInstructionGotoTable(this.l3RoutingTable);

		List<OFInstruction> serverToClientInstructionsList = new ArrayList<OFInstruction>();
		serverToClientInstructionsList.add(applyActionsServerToClient);
		serverToClientInstructionsList.add(serverToClientGoto);

		// Install Rules for SERVER -> CLIENT connection
		SwitchCommands.installRule(sw, this.table, (short) (SwitchCommands.DEFAULT_PRIORITY + (short) 2),
				serverToClientMatch, serverToClientInstructionsList, (short) 0, (short) 20);

		//-----------------------------------------------------------------------------------------------------------//

		return;
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(
				null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
		public void switchRemoved(long switchId) 
		{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
		public void switchActivated(long switchId)
		{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
		public void switchPortChanged(long switchId, ImmutablePort port,
				PortChangeType type) 
		{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
		public void switchChanged(long switchId) 
		{ /* Nothing we need to do */ }

	/**
	 * Tell the module system which services we provide.
	 */
	@Override
		public Collection<Class<? extends IFloodlightService>> getModuleServices() 
		{ return null; }

	/**
	 * Tell the module system which services we implement.
	 */
	@Override
		public Map<Class<? extends IFloodlightService>, IFloodlightService> 
		getServiceImpls() 
		{ return null; }

	/**
	 * Tell the module system which modules we depend on.
	 */
	@Override
		public Collection<Class<? extends IFloodlightService>> 
		getModuleDependencies() 
		{
			Collection<Class<? extends IFloodlightService >> floodlightService =
				new ArrayList<Class<? extends IFloodlightService>>();
			floodlightService.add(IFloodlightProviderService.class);
			floodlightService.add(IDeviceService.class);
			return floodlightService;
		}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
		public String getName() 
		{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
		public boolean isCallbackOrderingPrereq(OFType type, String name) 
		{
			return (OFType.PACKET_IN == type 
					&& (name.equals(ArpServer.MODULE_NAME) 
						|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
		}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
		public boolean isCallbackOrderingPostreq(OFType type, String name) 
		{ return false; }
}
