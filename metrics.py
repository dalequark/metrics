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
MIGRATE = 0.7
PROBE_INTERVAL = 3
VERBOSE = 1
MAXVALUE = None 

class metrics(DynamicPolicy):
 
    def __init__(self): 
        super(metrics,self).__init__()

        # Probing attributes
	self.network = None
        self.topology = None
	self.logger = None	
        self.timer = None
        self.lock = threading.Lock()
        self.ipToSwitch = {} 
	self.seqCounter = 0
	# rather than use sequence number, we use alternating black/white
        # packets, where this is the packet 'protocol'
        self.switchToPort = None
        # Policies, callbacks, etc
        self.newIpQuery = packets(1,['srcip'])
	self.newIpQuery.register_callback(self.registerIp)
	self.query = packets()
        self.query.register_callback(self.registerProbe) 
        self.macLearn = self.newIpQuery + mac_learner() 
	self.policy = self.macLearn
        self.floodPolicy = flood()
        self.dropPolicy = drop
	self.metricsPolicy = None
	self.reRoutingPolicy = None	
	self.inverseRoutingPolicy = None
	self.testquery = packets()
	if VERBOSE==1:
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
	print "registering ip ", ip
	
	self.ipToSwitch[ip] = switch
	self.updateReRoutingPolicy()
	self.updatePolicy()
 
    def updatePolicy(self):
	print "Updating policy..."
	probingPolicy = self.query if not self.metricsPolicy else self.metricsPolicy + self.query
	# Create rules based on the entries in the pendingResponses Table
	if self.reRoutingPolicy:
		self.policy = if_(match(srcip= PROBEIP), probingPolicy, self.testquery + (self.reRoutingPolicy >> self.macLearn))
		#self.policy = if_(match(srcip= PROBEIP), probingPolicy, self.testquery + (self.reRoutingPolicy >> self.metricsPolicy))
	else:
		self.policy = if_(match(srcip= PROBEIP), probingPolicy, self.testquery + self.macLearn)


    def updateReRoutingPolicy(self):

	thisPolicy = identity

	for pair in self.logger.switchPairs:
		pair = self.logger.switchPairs[pair]
		inSwitch = pair.inSwitch
		outSwitch = pair.outSwitch
		bestPort = pair.bestPort
		relevantIps = [ip for ip in self.ipToSwitch if self.ipToSwitch[ip] == outSwitch]

		for ip in relevantIps:
		 	thisPolicy = if_(match(switch=inSwitch) & match(dstip=ip), fwd(bestPort), thisPolicy)


	self.reRoutingPolicy = thisPolicy
	
	

    def registerProbe(self,pkt):
	with self.lock:
		self.logger.register(pkt)
		if self.logger.needsUpdate:
			self.updateReRoutingPolicy()
			self.updatePolicy()		
			self.logger.needsUpdate = False

    def probeAll(self):

	if self.seqCounter ==  65535:
		self.seqCounter = 0
      
	self.seqCounter += 1
 
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
                        self.sendPacket(switch, port, IPAddr(baseip+str(switch)), self.seqCounter)

    
    def set_network(self, network):
        super(metrics,self).set_network(network)
		
	self.network = network       
        self.topology = network.topology
      	MAXVALUE = len(self.topology.nodes())
	self.logger = probeLogger(self.topology)

	if self.timer:
            self.timer.cancel()
         
        self.pendingResponses = None
        
	self.installInitRules()
	self.updatePolicy()
 	
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
	def __init__(self, topology):
		self.topology = topology
		self.switchPairs = {}	
		self.currentRoute = {}
	# Represents every pair of switches a,b (where order matters)
	class switchPair:
		def __init__(self, inSwitch, outSwitch):
			self.inSwitch = inSwitch
			self.outSwitch = outSwitch
			self.mostRecentSeq = None
			self.bestPort = None
			self.bestInterSwitch = None
			self.probeMetrics = {}	
			self.counter = 1
			self.needsUpdate = False

		def addProbe(self,interSwitch, inPort, seqNo, logger):
			#print "Adding probe between ", self.inSwitch, " ", self.outSwitch, " through ", interSwitch
			self.counter += 1

			if seqNo < self.mostRecentSeq:
				self.probeMetrics[interSwitch] = self.__ewma(interSwitch, MAXVALUE)	
			elif seqNo == self.mostRecentSeq:
				self.probeMetrics[interSwitch] = self.__ewma(interSwitch, self.counter)	
			else:
				#print "Got first probe with seq ", seqNo, " from ", self.inSwitch, " to ", self.outSwitch, " through ", interSwitch
				self.counter = 1
				self.mostRecentSeq = seqNo
				self.probeMetrics[interSwitch] = self.__ewma(interSwitch, self.counter)	
			
			if not self.bestPort or self.probeMetrics[interSwitch] < MIGRATE*self.probeMetrics[self.bestInterSwitch]:
				# avoid creating routing loops
				otherPair = logger.switchPairs.get((interSwitch, self.outSwitch), None) 
				if not otherPair or otherPair.bestInterSwitch !=  self.inSwitch:
					if otherPair and otherPair.bestInterSwitch == self.inSwitch:
						return	
					self.bestInterSwitch = interSwitch
					self.bestPort = inPort 
					self.needsUpdate = True
											
		# Updates metric for route from inswitch to outswitch through interswitch				
		def __ewma(self,interSwitch, order):
			metric = self.probeMetrics.get(interSwitch, order)
			return metric*EWMA + (1-EWMA)*order

		def __str__(self):
			return "Pair between " + str(self.inSwitch) +" and " + str(self.outSwitch) + " best switch is " +str(self.bestInterSwitch)

	def __str__(self):
		return str('\n'.join([str(self.switchPairs[key]) for key in self.switchPairs]))
	
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
		thisPair = self.switchPairs.get((proberSwitch,responderSwitch), self.switchPair(proberSwitch,responderSwitch))	 	 
		
		thisPair.addProbe(interSwitch, inPort, seqNo, self)	
		self.switchPairs[(proberSwitch,responderSwitch)] = thisPair
		if thisPair.needsUpdate:
			self.needsUpdate = True
			thisPair.needsUpdate = False		
		
def main():
    print "RInitializing ..."
    return metrics() 

