from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.mac_learner import mac_learner
import multiprocessing 
import time, sched
import inspect
PROBEIP = IPAddr("1.2.3.4")
TIMEOUT = 5
PORT_START = 49152
MAX_PORTS = 65535 - 49153 

def sendPacket(sourceSwitch,dstip):
   # port 2 of 1 is linked to port 2 of 2 
    rp = Packet()
    dstmac = EthAddr("00:00:00:00:00:01")
    srcmac = dstmac   
     
    rp = rp.modify(switch=sourceSwitch)
    rp = rp.modify(inport=-1)
    rp = rp.modify(outport=outport)
    rp = rp.modify(srcip=IPAddr(PROBEIP))
    rp = rp.modify(dstmac=dstmac)
    rp = rp.modify(dstip=PROBEIP)
    rp = rp.modify(srcmac=srcmac) 
    rp = rp.modify(srcport=srcport)
    rp = rp.modify(ethtype=TCP_TYPE)
    rp = rp.modify(raw="")
    rp = rp.modify(protocol=1)
    network.inject_packet(rp)    

    
class metrics(DynamicPolicy):
 
    def __init__(self): 
        super(metrics,self).__init__()

        # Probing attributes
        self.topology = None
        self.probeTagsPolicy = flood() 
        
        # this is switch --> tcp srcport
        self.portMapping = None
        self.pendingResponses = None 
        self.query = packets()
        self.query.register_callback(self.printPack) 
        self.policy = self.query + mac_learner()
        self.floodPolicy = flood()
        self.dropPolicy = drop()
  #       policy = if_(match(srcip=IPAddr(PROBEIP)) & match(switch=4), self.query, mac_learner())
#        self.policy = self.probeTagsPolicy >> policy 
        self.policy = mac_learner()    

    def printPack(self,pkt):
       print pkt 
 
    def sendProbes(self, network, switch):
        ports = [port for port in network.topology.node[switch]['ports']]
        for port in ports:
           sendPacket(network,switch,port) 
    
    def switch_search(switchNum):
        for port in self.topology.node[switchNum]['ports']:
            if port.linked_to != None:
                sendProbe() 
    def set_network(self, network):
        super(metrics,self).set_network(network)
        self.topology = network.topology
        if len(network.topology.nodes()) > MAX_PORTS:
           print "Could not do metrics, too many switches"
           return
        
        metrics_policy = None
        # We install a rule at each switch
        for node in network.topology.nodes():
            thisPolicy = None
            for port in self.topology.node[node]['ports']:
                srcSwitch = port.linked_to
                # If this switch received this probe packet from source (because the srcport probe matched), then flood it, otherwise drop it. In any case, query it. 
                thisPolicy = thisPolicy + self.query + if_(match(srcport=PORT_START+srcSwitch), self.floodPolicy, self.dropPolicy) 
            metrics_policy = metrics_policy + thisPolicy

'''
        with self.lock:
            if self.topology and (self.topology == network.topology):
                pass
            else:
                self.topology = network.topology
                self.topology = network.topology
                self.portToSwitch = [None for x in self.topology.nodes()]
                for node in self.topology.nodes():
                    if node in self.portToSwitch:
                        self.portToSwitch[node] = [port.linked_to for port in self.topology.node[nodes]['ports']]
            inPort = pkt['outport']
            inSwitch = pkt['switch']
            sourceSwitch = self.portToSwitch[inSwitch][inPort]
            print "Got a probe from ", sourceSwitch 
'''
'''
    def printPack(self,pkt):
         print "Got a probe from " + str(pkt['srcmac'])
        print "Caught something"
        print "Looking at query from switch " + str(pkt['switch']) + " and srcip " + str(pkt['srcip'])
        if(str(pkt['srcip']) == '10.0.0.1'):
            print "Got message from 10.0.0.1." 
            if self.network:
                print "Sending probe..."
                sendProbe(self.network,pkt)
        if(str(pkt['srcip']) == PROBEIP):
            print "Got a probe back!"
            #print "Got a probe back from " + int(pkt['switch']) 
'''
def main():
    print "Initializing ..."
    return metrics() 

