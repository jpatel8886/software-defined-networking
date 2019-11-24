package edu.wisc.cs.sdn.apps.l3routing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.wisc.cs.sdn.apps.util.Host;

import org.openflow.protocol.*;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import edu.wisc.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.IFloodlightProviderService;
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
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.routing.Link;

public class L3Routing implements IFloodlightModule, IOFSwitchListener, 
       ILinkDiscoveryListener, IDeviceListener
{
	public static final String MODULE_NAME = L3Routing.class.getSimpleName();

	// Interface to the logging system
	private static Logger log = LoggerFactory.getLogger(MODULE_NAME);

	// Interface to Floodlight core for interacting with connected switches
	private IFloodlightProviderService floodlightProv;

	// Interface to link discovery service
	private ILinkDiscoveryService linkDiscProv;

	// Interface to device manager service
	private IDeviceService deviceProv;

	// Switch table in which rules should be installed
	public static byte table;

	// Map of hosts to devices
	private Map<IDevice,Host> knownHosts;

	public int INFINITE = 99999;

	public long recentlyAddedSwitch;

	// holds shortest paths for each switch 
	public Map<Long, HashMap<Long, destVertex>> bellmanMap = new ConcurrentHashMap<Long, HashMap<Long, destVertex>>(); 

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Loads dependencies and initializes data structures.
	 */
	@Override
		public void init(FloodlightModuleContext context)
		throws FloodlightModuleException 
		{
			log.info(String.format("Initializing %s...", MODULE_NAME));
			Map<String,String> config = context.getConfigParams(this);
			table = Byte.parseByte(config.get("table"));

			this.floodlightProv = context.getServiceImpl(
					IFloodlightProviderService.class);
			this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
			this.deviceProv = context.getServiceImpl(IDeviceService.class);

			this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	public HashMap <Long, destVertex> computeMiniMap (IOFSwitch srcSwitch) {

		HashMap <Long, destVertex> newMap = new HashMap<Long, destVertex>();

		Map <Long, IOFSwitch> realSwitches = this.getSwitches();
		Collection <Link> realLinks = this.getLinks();

		// Initialize distance to all other vertices as Infinite, srcSwitch as 0
		for (Long realSwitchId : realSwitches.keySet()) {
			if ((long)realSwitchId == (long)srcSwitch.getId()) {
				destVertex self = new destVertex(0, -1);
				self.setPrevPort(-1);
				newMap.put(realSwitchId, self);
			}
			else {
				destVertex self = new destVertex(this.INFINITE, -1);
				self.setPrevPort(-1);
				newMap.put(realSwitchId, self);
			}

		}

		int possibleDist;
		long tempDestSwitch;
		long tempSrcSwitch;
		boolean linksFound = false;

		// iterate over all switches in the real graph
		for (Long realSwitchID : realSwitches.keySet()) {

			// iterate over all edges in the original graph
			for (Link realLink : realLinks) {

				linksFound = true;

				tempSrcSwitch = realLink.getSrc();
				tempDestSwitch = realLink.getDst();
				possibleDist = newMap.get(tempSrcSwitch).getDistance() + 1;


				if (possibleDist >= this.INFINITE) {
					continue;
				}

				// if reaching this new destination vertex via this temporary source is cheaper
				if (possibleDist < newMap.get(tempDestSwitch).getDistance()) {
					newMap.get(tempDestSwitch).setDistance(possibleDist); // set new distance
					newMap.get(tempDestSwitch).setPrevId(tempSrcSwitch);  // set previous switch ID
					newMap.get(tempDestSwitch).setPrevPort(realLink.getSrcPort()); // set prev port # to dstPort?    
				}
			}
		}

			
		// update next hop port for each destination switch from a src switch	
		for (long newSwitchId : newMap.keySet()) {
	
			// if its an unreachable switch, don't backtrack from it
			if (newMap.get(newSwitchId).getDistance() >= this.INFINITE) continue;
	
			// if its same as src, don't backtrack	
			if ((long)newSwitchId == (long)srcSwitch.getId()) continue;

			// currTempSwitch holds the predecessor of newSwitchId
			long currTempSwitch = newSwitchId;
		
			// while the predecessor isn't SRC	
			while ((long)(newMap.get(currTempSwitch)).getPrevId() != (long)srcSwitch.getId()) {
				currTempSwitch = newMap.get(currTempSwitch).getPrevId();	
			}

			// currTempSwitch should be directly connected to SRC here
			newMap.get(newSwitchId).setPrevPort(newMap.get(currTempSwitch).getPrevPort());			

		}

		return newMap;
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	* (1) Removes stale host rules
	* (2) Refreshes shortest paths
	* (3) Re-install new rules on switches
	*/

	public void recomputeBellmanMap() {

		// remove all stale rules 
		for (Host host : this.getHosts()) {
			this.uninstallHostRules(host);
		}
	
		// clear BellmanMap to install fresh shortest paths
		this.bellmanMap.clear();

		// compute fresh shortest paths
		Map <Long, IOFSwitch> realSwitches = this.getSwitches();
		for (IOFSwitch realSwitch : realSwitches.values()) {

			// compute mini map for this switch and store it as its value
			bellmanMap.put(realSwitch.getId(), computeMiniMap(realSwitch));
				
			HashMap<Long, destVertex> shortestPaths = bellmanMap.get(realSwitch.getId());			

			/** 	
			System.out.println("\n------------- Shortest Paths of: " + realSwitch.getId() + " -------------");
			for (Long shortestSwitch : shortestPaths.keySet()) {
				System.out.println("Switch " + shortestSwitch + " : " + shortestPaths.get(shortestSwitch));
			}
			System.out.println("----------------------------------------------------");		
			// */

		}	

		// Refresh rules on all switches
		for (Host host : this.getHosts()) {
			if (!host.isAttachedToSwitch()) continue;
			this.installHostRules(host.getIPv4Address(), host.getPort(), host.getSwitch());
		}	
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	public void populateBellmanMap() {

		Map <Long, IOFSwitch> realSwitches = this.getSwitches();

		for (IOFSwitch realSwitch : realSwitches.values()) {

			// compute shortest path (bellman) map for each switch as a src,
			// and put that inside the global Bellman Map
			if (bellmanMap.containsKey(realSwitch.getId())) {
				bellmanMap.put(realSwitch.getId(), computeMiniMap(realSwitch));
			}
			else 
				System.out.println("WRONG! bellmanMap CONTAINS THIS SWITCH ALREADY");	
		}
	}

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Subscribes to events and performs other startup tasks.
	 */
	@Override
		public void startUp(FloodlightModuleContext context)
		throws FloodlightModuleException 
		{
			log.info(String.format("Starting %s...", MODULE_NAME));
			this.floodlightProv.addOFSwitchListener(this);
			this.linkDiscProv.addListener(this);
			this.deviceProv.addListener(this);

			/*********************************************************************/
			/* TODO: Initialize variables or perform startup tasks, if necessary */

			// fill up bellman map to have shortest paths for each switch
			populateBellmanMap(); 

			/*********************************************************************/
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Get a list of all known hosts in the network.
	 */
	private Collection<Host> getHosts()
	{ return this.knownHosts.values(); }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Get a map of all active switches in the network. Switch DPID is used as
	 * the key.
	 */
	private Map<Long, IOFSwitch> getSwitches()
	{ return floodlightProv.getAllSwitchMap(); }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Get a list of all active links in the network.
	 */
	private Collection<Link> getLinks()
	{ return linkDiscProv.getLinks().keySet(); }


	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when a host joins the network.
	 * @param device information about the host
	 */
	@Override
		public void deviceAdded(IDevice device) 
		{
			Host host = new Host(device, this.floodlightProv);	

			// We only care about a new host if we know its IP
			if (host.getIPv4Address() != null)
			{
				log.info(String.format("Host %s added", host.getName()));
				this.knownHosts.put(device, host);

				/*****************************************************************/
				/* TODO: Update routing: add rules to route to new host          */

				if (!host.isAttachedToSwitch()) {
					System.out.println("Host not attached to switch, rules not installed");
					return;
				}
					
				
				// use this host's parent switch's hashmap to install rules on every switches			
				installHostRules(host.getIPv4Address(), host.getPort(), host.getSwitch());

				/*****************************************************************/
			}
		}


	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when a host is no longer attached to a switch.
	 * @param device information about the host
	 */
	@Override
		public void deviceRemoved(IDevice device) 
		{
			Host host = this.knownHosts.get(device);
			if (null == host)
			{ return; }
			this.knownHosts.remove(device);

			log.info(String.format("Host %s is no longer attached to a switch", 
						host.getName()));

			/*********************************************************************/
			/* TODO: Update routing: remove rules to route to host               */

			uninstallHostRules(host);

			/*********************************************************************/
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when a host moves within the network.
	 * @param device information about the host
	 */
	@Override
		public void deviceMoved(IDevice device) 
		{
			Host host = this.knownHosts.get(device);
			if (null == host)
			{
				host = new Host(device, this.floodlightProv);
				this.knownHosts.put(device, host);
			}


			if (!host.isAttachedToSwitch())
			{
				this.deviceRemoved(device);
				return;
			}
			log.info(String.format("Host %s moved to s%d:%d", host.getName(),
						host.getSwitch().getId(), host.getPort()));

			/*********************************************************************/
			/* TODO: Update routing: change rules to route to host               */

			uninstallHostRules(host);
			installHostRules(host.getIPv4Address(), host.getPort(), host.getSwitch());

			/*********************************************************************/
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

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
			/* TODO: Update routing: change routing rules for all hosts          */

			recentlyAddedSwitch = switchId;

			recomputeBellmanMap();

			/*********************************************************************/
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
		public void switchRemoved(long switchId) 
		{
			IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
			log.info(String.format("Switch s%d removed", switchId));

			/*********************************************************************/
			/* TODO: Update routing: change routing rules for all hosts          */

			recomputeBellmanMap();

			/*********************************************************************/
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////
	
	/**
	* Remove rules concerning this host on all switches
	*/

	public void uninstallHostRules(Host host)
	{
		OFMatch removal = new OFMatch();
		removal.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		removal.setNetworkDestination(host.getIPv4Address());
		
		// traverse through all switches and remove this rule
		Map<Long, IOFSwitch> realSwitches = this.getSwitches();
		for (IOFSwitch realSwitch : realSwitches.values())
		{
			SwitchCommands.removeRules(realSwitch, this.table, removal);
		}


		return;
	}
	
	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	public void installHostRules (Integer hostIp, Integer hostPort, IOFSwitch parentSwitch) {

		OFMatch matchCriteria = new OFMatch();
		matchCriteria.setDataLayerType(OFMatch.ETH_TYPE_IPV4);
		matchCriteria.setField(OFOXMFieldType.IPV4_DST, hostIp);		

		OFAction actionOutput = new OFActionOutput(hostPort);

		List<OFInstruction> ofInstructionsList = new ArrayList<OFInstruction>();
		OFInstructionApplyActions ofApplyActions = new OFInstructionApplyActions();	
		List<OFAction> listOfActions = new ArrayList<OFAction>(); 

		listOfActions.add(actionOutput);
		ofApplyActions.setActions(listOfActions);
		ofInstructionsList.add(ofApplyActions);

		boolean ret1 = SwitchCommands.installRule(parentSwitch, this.table, 
					SwitchCommands.DEFAULT_PRIORITY, matchCriteria, ofInstructionsList, 
					SwitchCommands.NO_TIMEOUT, SwitchCommands.NO_TIMEOUT, OFPacketOut.BUFFER_ID_NONE);


		destVertex parentTarget;		

		Map <Long, IOFSwitch> realSwitches = this.getSwitches();
		
		// Iterate on all switches of the bellman map
		for (Long targetSwitch : bellmanMap.keySet()) {

			// for parent switch, rule is already set, skip it
			if (targetSwitch == parentSwitch.getId()) {
				continue;	
			}

			else {					
				// get the shortest path map for this switch
				HashMap<Long, destVertex> shortestPathMap = bellmanMap.get(targetSwitch);
		
				// get the port on which this switch can send out packet (shortest path to parent switch)
				parentTarget = shortestPathMap.get(parentSwitch.getId()); 	
				
				actionOutput = new OFActionOutput(parentTarget.getPrevPort());
				//actionOutput.setPort(parentTarget.getPrevPort()); 
			
				// construct the rest of the packet
				ofInstructionsList = new ArrayList<OFInstruction>();
				ofApplyActions = new OFInstructionApplyActions();	
				listOfActions = new ArrayList<OFAction>(); 

				listOfActions.add(actionOutput);
				ofApplyActions.setActions(listOfActions);
				ofInstructionsList.add(ofApplyActions);

				// Install this rule on this switch 
				boolean ret2 = SwitchCommands.installRule(realSwitches.get(targetSwitch), this.table, 
							SwitchCommands.DEFAULT_PRIORITY, matchCriteria, ofInstructionsList, 
							SwitchCommands.NO_TIMEOUT, SwitchCommands.NO_TIMEOUT, OFPacketOut.BUFFER_ID_NONE);
				
			}
		}
	}
	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
		public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
		{
			for (LDUpdate update : updateList)
			{
				// If we only know the switch & port for one end of the link, then
				// the link must be from a switch to a host
				if (0 == update.getDst())
				{
					log.info(String.format("Link s%s:%d -> host updated", 
								update.getSrc(), update.getSrcPort()));
				}
				// Otherwise, the link is between two switches
				else
				{
					log.info(String.format("Link s%s:%d -> s%s:%d updated", 
								update.getSrc(), update.getSrcPort(),
								update.getDst(), update.getDstPort()));	

				}
			}

			/*********************************************************************/
			/* TODO: Update routing: change routing rules for all hosts          */

			this.recomputeBellmanMap();		

			/*********************************************************************/
		}

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
		public void linkDiscoveryUpdate(LDUpdate update) 
		{ this.linkDiscoveryUpdate(Arrays.asList(update)); }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when the IP address of a host changes.
	 * @param device information about the host
	 */
	@Override
		public void deviceIPV4AddrChanged(IDevice device) 
		{ this.deviceAdded(device); }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when the VLAN of a host changes.
	 * @param device information about the host
	 */
	@Override
		public void deviceVlanChanged(IDevice device) 
		{ /* Nothing we need to do, since we're not using VLANs */ }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
		public void switchActivated(long switchId) 
		{ /* Nothing we need to do, since we're not switching controller roles */ }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
		public void switchChanged(long switchId) 
		{ /* Nothing we need to do */ }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

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
		{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
		public String getName() 
		{ return this.MODULE_NAME; }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
		public boolean isCallbackOrderingPrereq(String type, String name) 
		{ return false; }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
		public boolean isCallbackOrderingPostreq(String type, String name) 
		{ return false; }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Tell the module system which services we provide.
	 */
	@Override
		public Collection<Class<? extends IFloodlightService>> getModuleServices() 
		{ return null; }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Tell the module system which services we implement.
	 */
	@Override
		public Map<Class<? extends IFloodlightService>, IFloodlightService> 
		getServiceImpls() 
		{ return null; }

	///////////////////////////////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////////////////////////////

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
			floodlightService.add(ILinkDiscoveryService.class);
			floodlightService.add(IDeviceService.class);
			return floodlightService;
		}
}
