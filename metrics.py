from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.mac_learner import mac_learner
from pyretic.modules.arp import arp 
import time
from threading import Timer
import threading 
import inspect
PROBEIP = IPAddr("1.2.3.0")
baseip = "1.2.3."
TIMEOUT = 5
EWMA = 0.1
MIGRATE = 1.3
PROBE_INTERVAL = 3
WHITE = 1
BLACK = 2 # note protocol is a 16-bit field
VERBOSE = 1

class metrics(DynamicPolicy):
 
    def __init__(self): 
        super(metrics,self).__init__()

        # Probing attributes
	self.network = None
        self.topology = None
        self.timer = None
        self.lock = threading.Lock()
        self.ipToSwitch = {} 
	# rather than use sequence number, we use alternating black/white
        # packets, where this is the packet 'protocol'
        self.currentColor = WHITE
        self.switchToPort = None
        # Policies, callbacks, etc
        self.newIpQuery = packets(1,['srcip'])
	self.newIpQuery.register_callback(self.registerIp)
	self.query = packets()
        self.query.register_callback(self.registerProbe) 
        self.policy = mac_learner()
        self.floodPolicy = flood()
        self.dropPolicy = drop
        self.macLearn = self.newIpQuery + mac_learner() 
        self.metricsPolicy = None
	self.ipReroutePolicy = None	
	self.testquery = packets()
	if VERBOSE>0:
		self.testquery.register_callback(self.test)
	
    def test(self, pkt):
	print "Packet from ", pkt['srcip'], " to ", pkt['dstip'], " at ", pkt['switch']
	
    def sendPacket(self, sourceSwitch, outport, dstip, color):
            """Construct an arp packet from scratch and send"""
            dstmac = EthAddr("00:00:00:00:00:02")
            srcmac = dstmac   
            rp = Packet()
            rp = rp.modify(protocol=color)
            rp = rp.modify(ethtype=ARP_TYPE)
            rp = rp.modify(switch=sourceSwitch)
            rp = rp.modify(inport=-1)
            rp = rp.modify(outport=outport)
            rp = rp.modify(srcip=PROBEIP)
            rp = rp.modify(srcmac=srcmac)
            rp = rp.modify(dstip=dstip)
            rp = rp.modify(dstmac=dstmac)
            rp = rp.modify(raw='')
            self.network.inject_packet(rp)

    #Figure out what switch each ip corresponds to (so we can route based on switches)
    def registerIp(self, pkt):
	switch = pkt['switch']
	ip = pkt['srcip']
	self.ipToSwitch[ip] = switch
 
    def updatePolicy(self):
	with self.lock:
		probingPolicy = self.query if not self.metricsPolicy else self.metricsPolicy + self.query
		self.reroutingPolicy = None
		# Create rules based on the entries in the pendingResponses Table
		#print self.pendingResponses
		if self.pendingResponses:
			for srcSwitch in self.pendingResponses:
				thisSwitchRouting = None
				for destSwitch in self.pendingResponses[srcSwitch]:
					interSwitch = self.pendingResponses[srcSwitch][destSwitch]
					#get all of the relevant ips destined for destSwitch
					ips = [ip for ip in self.ipToSwitch if self.ipToSwitch[ip] == destSwitch]
					for ip in ips:
						newRule = match(dstip=ip) >> fwd(interSwitch)
						thisSwitchRouting = newRule if not thisSwitchRouting else thisSwitchRouting + newRule
				if thisSwitchRouting:
					thisSwitchRouting = match(switch=srcSwitch) >> thisSwitchRouting
					self.reroutingPolicy = thisSwitchRouting if not self.reroutingPolicy else self.reroutingPolicy + thisSwitchRouting
			if self.reroutingPolicy:
				self.policy = if_(match(srcip= PROBEIP), probingPolicy, self.testquery + self.reroutingPolicy + self.macLearn)
				return
		
		self.policy = if_(match(srcip= PROBEIP), probingPolicy, self.testquery + self.macLearn)


    def updateMetricsPolicy(self):
	newPolicy = None
	for pair in self.probeLogger.switchPairs:
		inSwitch = pair.inSwitch
		outSwitch = pair.outSwitch
		bestPort = pair.bestPort
		
		thisPol = None
		for ip in self.ipToSwitch if self.ipToSwitch[ip] == outSwitch:
			pol = match(dstip=ip) >> fwd(bestPort)
			thisPol = pol if not thisPol else thisPol + pol

		thisPol = match(switch=inSwitch) >> thisPol
		newPolicy = thisPol if not newPolciy else newPolicy + thisPolicy
	
	self.metricsPolicy = newPolicy
	self.updatePolicy()
	
    def registerProbe(self,pkt):
        with self.lock:
                responderSwitch = pkt['switch']
                proberSwitch = int(str(pkt['dstip'])[6:])
		# prevents against 1-cycle-old probes
                if not pkt['protocol'] == self.currentColor:
                    pass
                elif not responderSwitch in self.pendingResponses[proberSwitch]:
                    # Okay, this is the first packet that got to responSwitch from proberSwitch 
                    # How did it get to responSwitch? Directly or through an intermediary?
                    # Check to see what inport responSwitch got this packet on:
                    inPort = pkt['inport']
                    #this is switch[port]
                    interSwitch = self.topology.node[responderSwitch]['ports'][inPort].linked_to
                    interSwitch = int(str(interSwitch)[:str(interSwitch).find('[')])            
                    if proberSwitch == interSwitch:
                        self.pendingResponses[proberSwitch][responderSwitch] = self.switchToPort[proberSwitch][responderSwitch]
                    else:
                        self.pendingResponses[proberSwitch][responderSwitch] = self.switchToPort[proberSwitch][interSwitch] 

    
    def probeAll(self):
	# We should update anything in the previous probe table because it's about to be wiped.
	self.updatePolicy()
        color = self.currentColor
        self.currentColor = WHITE if color == BLACK else BLACK 
        
        for switch in self.topology.nodes():
            self.sendProbes(switch)
   
	# restart the timer 
        self.timer.cancel() 
        self.timer = Timer(PROBE_INTERVAL, self.probeAll)
        self.timer.start()

    def sendProbes(self, switch):
        if self.topology:

                ports = [port for port in self.topology.node[switch]['ports']]
                for port in ports:
                    connectedSwitch = self.topology.node[switch]['ports'][port].linked_to
                    if connectedSwitch != None:
                        self.sendPacket(switch, port, IPAddr(baseip+str(switch)), self.currentColor)

    
    def set_network(self, network):
        super(metrics,self).set_network(network)
	
	self.network = network       
        self.topology = network.topology
       
	if self.timer:
            self.timer.cancel()
         
        
	self.installInitRules()
	
	# restart the probing timer
        self.timer = Timer(PROBE_INTERVAL, self.probeAll)
        self.timer.start()    


    def installInitRules(self):
	network = self.network
        self.switchToPort = {}
        
        metrics_policy = None 

        # We install a rule at each switch
        for node in network.topology.nodes():
            thisPolicy = None
	    self.switchToPort[node] = {}
            for port in self.topology.node[node]['ports']:
                #srcSwitch is the switch from which node receieves data on port
		srcSwitch = self.topology.node[node]['ports'][port].linked_to
                if not srcSwitch == None:
                    srcSwitch= int(srcSwitch.switch)
                    self.switchToPort[node][srcSwitch] = port
                # If this switch received this probe packet from source (because the srcport probe matched), then flood it, otherwise drop it. In any case, query it.
                    matchCondition = match(dstip=IPAddr(baseip+str(srcSwitch)) ) & match(inport = port) 
		    if thisPolicy:
		    	thisPolicy = thisPolicy +if_(match(switch=node) & matchCondition, self.floodPolicy, self.dropPolicy) 
		    else:
			thisPolicy = if_(match(switch=node) & matchCondition, self.floodPolicy, self.dropPolicy)
	    if metrics_policy:
            	metrics_policy = metrics_policy + thisPolicy
            else:
		metrics_policy = thisPolicy

        self.metricsPolicy = metrics_policy      
        self.updatePolicy()

class probeLogger:
	def __init__(self):
		self.switchPairs = {}
		self.requiresUpdate = False
	
	# Represents every pair of switches a,b (where order matters)
	class switchPair:
		def __init__(self, inSwitch, outSwitch):
			self.inSwitch = inSwitch
			self.outSwitch = outSwitch
			self.mostRecentSeq = None
			self.bestPort = None
			self.probeMetrics = {}	
			self.counter = 1

		def addProbe(self,interSwitch,seqNo):
			# If this probe got extermely delayed ...
			if seqNo < self.mostRecentSeq:
				self.probeMetrics[interSwitch] = self.__ewma(interSwitch, MAX_ORDER)	
				return
		
			if seqNo > self.mostRecentSeq:
				self.mostRecentSeq = seqNo
				self.counter = 1	
			else:
				self.counter += 1
		
			thisMetric = self.__ewma(interSwitch, self.counter)		
			self.probeMetrics[interSwitch] = thisMetric
			
			#check to see if this probe is so good that we need to update the flow table
			if thisMetric > self.probeMetrics[self.bestPort]*MIGRATE:
				self.bestPort = thisMetric
				probeLogger.requiresUpdate = True
					
		# Updates metric for route from inswitch to outswitch through interswitch				
		def __ewma(self,interSwitch, order):
			metric = self.probeMetrics.get(interSwitch, order)
			return metric*EWMA + (1-EWMA)*order
		
	def register(self,pkt):
		# Figure where this probe came from, who sent it, etc.
		seqNo = pkt['protocol']
		responderSwitch = pkt['switch']
                proberSwitch = int(str(pkt['dstip'])[6:])
                
		# Use inport to determine who sent this packet to responderSwitch
		inPort = pkt['inport']
                interSwitch = self.topology.node[responderSwitch]['ports'][inPort].linked_to
                interSwitch = int(str(interSwitch)[:str(interSwitch).find('[')])           		
		# Either get the existing object for this switchPair or make a new one 
		thisPair = self.switchPairs.get((proberSwitch,responderSwitch), switchPair((proberSwitch,responderSwitch)))	 	 
		
		thisPair.addProbe(interSwitch, seqNo)	
		
		self.switchPairs[(proberSwitch,responderSwitch)] = thisPair
	
			
		
def main():
    test()
    print "RInitializing ..."
    return metrics() 

