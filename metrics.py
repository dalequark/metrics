from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.mac_learner import mac_learner
import multiprocessing 
import time
from threading import Timer
import inspect
PROBEIP = IPAddr("1.2.3.0")
baseip = "1.2.3."
TIMEOUT = 5
PROBE_INTERVAL = 3
class metrics(DynamicPolicy):
 
    def __init__(self): 
        super(metrics,self).__init__()

        # Probing attributes
        self.topology = None
        self.pendingResponses = None
        #[srcSwitch][dstSwitch] = port on srcSwitch to get to dstSwitch 
        self.switchToPort = None
        # Policies, callbacks, etc
        self.query = packets()
        self.query.register_callback(self.printPack) 
        self.policy = mac_learner()
        self.floodPolicy = flood()
        self.dropPolicy = drop
        self.macLearner = mac_learner()
        self.metricsPolicy = None

    def sendPacket(self, sourceSwitch, outport, dstip):
            """Construct an arp packet from scratch and send"""
            dstmac = EthAddr("00:00:00:00:00:02")
            srcmac = dstmac   
            rp = Packet()
            rp = rp.modify(protocol=1)
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

    def updatePolicy(self):
        self.policy =if_(match(srcip= PROBEIP), self.query + self.metricsPolicy, self.macLearner) 
        self.policy = if_(match(srcip= PROBEIP), self.query, self.macLearner) 
    def registerProbe(self,pkt):
        responderSwitch = pkt['switch']
        proberSwitch = int(pkt['srcport']) - PORT_START
        if self.pendingRequests[proberSwitch][responderSwitch] == None:
            # Okay, this is the first packet that got to responSwitch from proberSwitch 
            # How did it get to responSwitch? Directly or through an intermediary?
            # Check to see what inport responSwitch got this packet on:
            inPort = pkt['inport']
            interSwitch = self.topology.node[responderSwitch]['ports'][inPort].linked_to
            self.pendingRequests[proberSwitch][responderSwitch] = self.switchToPort[proberSwitch][interSwitch] 
             
        
    def printPack(self,pkt):
        print pkt
        Timer(PROBE_INTERVAL, self.probeAll, ()).start()
    def probeAll(self):
        self.pendingResponses = {}
        for switch in self.topology.nodes():
            self.pendingResponses[switch] = {}
            self.sendProbes(switch)
  
    def sendProbes(self, switch):
        if self.topology:
                ports = [port for port in self.topology.node[switch]['ports']]
                for port in ports:
                    if self.topology.node[switch]['ports'][port].linked_to != None:
                        print "sending probe from ", switch, " to ", port    
                        self.pendingResponses[switch][port] = None 
                        self.sendPacket(switch, port, IPAddr(baseip+str(switch))) 
    

    def set_network(self, network):
        super(metrics,self).set_network(network)
        print "Setting Network"
        self.pendingResponses = None
        self.topology = network.topology
        self.switchToPort = {}
        
        metrics_policy = identity

        # We install a rule at each switch
        for node in network.topology.nodes():
            self.switchToPort[node] = {}
            thisPolicy = identity
            for port in self.topology.node[node]['ports']:
                srcSwitch = self.topology.node[node]['ports'][port].linked_to
                if not srcSwitch == None:
                    srcSwitch= int(srcSwitch.switch)
                    self.switchToPort[node][srcSwitch] = port
                # If this switch received this probe packet from source (because the srcport probe matched), then flood it, otherwise drop it. In any case, query it. 
                    thisPolicy = thisPolicy + match(switch = node) >> if_(match(dstip=IPAddr(baseip+str(srcSwitch))), self.floodPolicy, self.dropPolicy) 
            thisPolicy = match(switch=node) >> thisPolicy
            metrics_policy = metrics_policy + thisPolicy

        self.metricsPolicy = metrics_policy       
        self.updatePolicy()

        # restart the probing timer
    
        Timer(PROBE_INTERVAL, self.probeAll, ()).start()
    

def main():
    print "Initializing ..."
    return metrics() 

