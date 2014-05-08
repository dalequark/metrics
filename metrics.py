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
EWMA = 0.3
MIGRATE = 0.9
PROBE_INTERVAL = 3
VERBOSE = 2
MAXVALUE = 7 

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
        self.ipRules = None
	self.macLearn = mac_learner() 
	self.policy = self.macLearn
        self.floodPolicy = flood()
        self.dropPolicy = drop
	self.metricsPolicy = None
	self.reRoutingPolicy = None	
	self.inverseRoutingPolicy = None
	self.testquery = self.newIpQuery 
	self.test2q = packets()
	self.test3q = packets()
	self.test4q = packets()
	self.test4q.register_callback(self.test2)
	self.test3q.register_callback(self.test)
	self.test5q = packets()
	self.test5q.register_callback(self.test3)
	#self.test2q.register_callback(self.test)

	self.rulesSelfCheck = {}

    def test2(self,pkt):
	print "had a rule for ", pkt['srcip'], "->", pkt['dstip']

    def test3(self,pkt):
	print "had no rule for ", pkt['srcip'], "->", pkt['dstip']

    def test(self, pkt):
	if VERBOSE == 2: print "Packet from ", pkt['srcip'], " to ", pkt['dstip'], " at ", pkt['switch']
	try:
		inSwitch = self.ipToSwitch[pkt['srcip']]
		outSwitch = self.ipToSwitch[pkt['dstip']]
		print self.logger.switchPairs[(inSwitch, outSwitch )]	
		print "Self check say ", self.rulesSelfCheck[(inSwitch, outSwitch)]
	except:
		pass
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
	inport = pkt['inport']
	#print "registering ip ", ip
	
	self.ipToSwitch[ip] = switch
	self.ipRules = drop if not self.ipRules else self.ipRules
	self.ipRules = if_(match(dstip=ip) & match(switch=switch), fwd(inport), self.ipRules)

	self.updateReRoutingPolicy()
	self.updatePolicy()
 
    def updatePolicy(self):
	#print "Updating policy..."
	probingPolicy = self.query if not self.metricsPolicy else self.metricsPolicy + self.query
	# Create rules based on the entries in the pendingResponses Table
	if self.reRoutingPolicy:
		p = if_(match(srcip=IPPrefix('10.9.0.0/16')) & match(dstip=IPPrefix('10.9.0.0/16')),  self.test2q + self.macLearn,  self.test3q + self.testquery + (self.reRoutingPolicy)) 
		self.policy = if_(match(srcip= PROBEIP), probingPolicy, p) 
	else:
		p = if_(match(srcip=IPPrefix('10.9.0.0/16')) & match(dstip=IPPrefix('10.9.0.0/16')), self.test2q + self.macLearn, self.test3q + self.testquery) 
		self.policy = if_(match(srcip= PROBEIP), probingPolicy, p)


    def updateReRoutingPolicy(self):

	thisPolicy = self.ipRules

	for pair in self.logger.switchPairs:
		pair = self.logger.switchPairs[pair]
		inSwitch = pair.inSwitch
		outSwitch = pair.outSwitch
		try:
			bestPort = self.switchToPort[inSwitch][pair.bestInterSwitch]	
		except KeyError:
			assert pair.bestInterSwitch == inSwitch	
			bestPort = self.switchToPort[inSwitch][outSwitch]

		relevantIps = [ip for ip in self.ipToSwitch if self.ipToSwitch[ip] == outSwitch]
		
		for ip in relevantIps:
			assert inSwitch != outSwitch
			self.rulesSelfCheck[(inSwitch, outSwitch)] = self.topology.node[inSwitch]['ports'][bestPort].linked_to.switch
		 	thisPolicy = if_(match(switch=inSwitch) & match(dstip=ip), self.test4q + fwd(bestPort), thisPolicy)
	
		
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
	if self.timer:
            self.timer.cancel()
        
	super(metrics,self).set_network(network)
	self.network = network       
        self.topology = network.topology
      	MAXVALUE = 7

	self.logger = probeLogger(self.topology)

         
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

class probeLogger:
	def __init__(self, topology):
		self.topology = topology
		self.switchPairs = {}	
		self.currentRoute = {}
		self.needsUpdate = False
	
	# Represents every pair of switches a,b (where order matters)
	class switchPair:
		def __init__(self, inSwitch, outSwitch):
			self.inSwitch = inSwitch
			self.outSwitch = outSwitch
			self.mostRecentSeq = None
			self.bestPort = None
			self.bestInterSwitch = None
			self.probeMetrics = {}	
			self.lastProbeSeq = {}
			self.counter = 1
			self.needsUpdate = False

		def addProbe(self,interSwitch, seqNo, logger):
			#print "Adding probe between ", self.inSwitch, " ", self.outSwitch, " through ", interSwitch
			self.counter += 1
			self.lastProbeSeq[interSwitch] = seqNo
			if seqNo >= 65535:
				print "Got seq no ", seqNo, " --------"+"-"*10	
			if seqNo < self.mostRecentSeq and not self.mostRecentSeq == 65535 or (self.mostRecentSeq < 20000 and seqNo > 40000):
				self.probeMetrics[interSwitch] = self.__ewma(interSwitch, MAXVALUE)	
			elif seqNo == self.mostRecentSeq:
				self.probeMetrics[interSwitch] = self.__ewma(interSwitch, self.counter)	
			else:
				#print "Got first probe with seq ", seqNo, " from ", self.inSwitch, " to ", self.outSwitch, " through ", interSwitch
				# Apply a penalty to probes that were not recieved during this seq number round  
				for switch in [x for x in self.lastProbeSeq if self.lastProbeSeq[x] < self.mostRecentSeq]:
					self.probeMetrics[x] = self.__ewma(x, MAXVALUE) 
				self.counter = 1
				self.mostRecentSeq = seqNo
				self.probeMetrics[interSwitch] = self.__ewma(interSwitch, self.counter)	
				
			
				
			'''			
			if self.inSwitch == 4 and self.outSwitch == 1 and not self.inSwitch == interSwitch:
				try:
					print "in ", self.inSwitch, " out ", self.outSwitch, " best inter ", self.bestInterSwitch, " new inter ", interSwitch
					print " metric ", self.probeMetrics[self.bestInterSwitch], " new metric ", self.probeMetrics[interSwitch]	
				except KeyError:
					pass
			'''

			if not self.bestInterSwitch or self.probeMetrics[interSwitch] < MIGRATE*self.probeMetrics[self.bestInterSwitch]:
				# avoid creating routing loops
				otherPair = logger.switchPairs.get((interSwitch, self.outSwitch), None) 
				if not otherPair or otherPair.bestInterSwitch !=  self.inSwitch:
					self.bestInterSwitch = interSwitch
					self.needsUpdate = True
											
		# Updates metric for route from inswitch to outswitch through interswitch				
		def __ewma(self,interSwitch, order):
			metric = self.probeMetrics.get(interSwitch, order)
			return metric*EWMA + (1-EWMA)*order

		def __str__(self):
			return "| %d -> %d | %d | %f |" % (self.inSwitch, self.outSwitch, self.bestInterSwitch, self.probeMetrics[self.bestInterSwitch])
	def __str__(self):
		return "-"*30 + '\n' + str('\n'.join([str(self.switchPairs[key]) for key in self.switchPairs]))
	
	def register(self,pkt):
		
		# Figure where this probe came from, who sent it, etc.
		seqNo = pkt['protocol']
		responderSwitch = pkt['switch']
                
		proberSwitch = int(str(pkt['dstip'])[6:])
                
		
		# Use inport to determine who sent this packet to responderSwitch
		inPort = pkt['inport']
                interSwitch = self.topology.node[responderSwitch]['ports'][inPort].linked_to.switch
	
		#print "From %d to %d through %d with seq no %d" % (proberSwitch, responderSwitch, interSwitch, seqNo)	
		
		# Either get the existing object for this switchPair or make a new one 
		thisPair = self.switchPairs.get((proberSwitch,responderSwitch), self.switchPair(proberSwitch,responderSwitch))	 	 
		thisPair.addProbe(interSwitch, seqNo, self)	
		self.switchPairs[(proberSwitch,responderSwitch)] = thisPair
		if thisPair.needsUpdate:
			self.needsUpdate = True
			thisPair.needsUpdate = False		
			if VERBOSE == 2: print self	
def main():
    print "RInitializing ..."
    return metrics() 

