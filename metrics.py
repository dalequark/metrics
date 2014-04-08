from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.mac_learner import mac_learner
from multiprocessing import Lock
import time, sched
PROBEIP = "1.2.3.4"
TIMEOUT = 5
 
def sendPacket(network,switch,outport):
   # port 2 of 1 is linked to port 2 of 2 
    rp = Packet()
    
    rp = rp.modify(switch=switch)
    rp = rp.modify(inport=-1)
    rp = rp.modify(outport=outport)
    rp = rp.modify(srcip=IPAddr(PROBEIP))
    rp = rp.modify(dstmac=pkt['dstmac'])
    rp = rp.modify(dstip=pkt['dstip'])
    rp = rp.modify(srcmac=pkt['srcmac']) 
    rp = rp.modify(ethtype=ARP_TYPE)
    rp = rp.modify(raw="")
    rp = rp.modify(protocol=1)
    rp = rp.modify(ethtype=ARP_TYPE)
    network.inject_packet(rp)    

class metrics(DynamicPolicy):
 
    def __init__(self): 
        super(metrics,self).__init__()
        self.topology = None
        self.lock = Lock()
        self.linkMetrics = []
        self.nodes = []
        self.portToSwitch = None 
        self.pendingPackets = []
        self.query = packets()
        self.query.register_callback(self.printPack)
        policy = if_(match(srcip=IPAddr(PROBEIP)), self.query, mac_learner())
        self.policy = policy 
        self.topology = None
       
    def sayHello(self):
        print "Say hello"
 
'''
    def sendProbe(self, network, switch):
        ports = [port for port in network.topology.node[switch]['ports']]
        for port in ports:
           sendPacket(network,switch,port) 
    
    def set_network(self, network):
        with self.lock:
            if self.topology and (self.topology == network.topology):
                pass
            else:
                self.topology = network.topology
                self.portToSwitch = [None for x in self.topology.nodes()]
                for node in self.topology.nodes():
                    if node in self.portToSwitch:
                        self.portToSwitch[node] = [port.linked_to for port in self.topology.node[nodes]['ports']]
            print "From setnetwork, active count is ", threading.active_count(), " from pid ", threading.current_thread().name
            threading.Timer(5, self.sayHello, ()).start()
            print "After timer, active count is ", threading.active_count(), " from pid ", threading.current_thread().name
'''
        
    def printPack(self,pkt):
       print "Logger" 
    def logPacket(self,pkt):
        # If this packet came in on port, switch, where did it come from?
        print "Logged"
'''
            inPort = pkt['outport']
            inSwitch = pkt['switch']
            sourceSwitch = self.portToSwitch[inSwitch][inPort]
            print "Got a probe from ", sourceSwitch 
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
    return metrics()

