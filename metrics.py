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
counter = 0


class metrics(DynamicPolicy):
 
    def __init__(self): 
        super(metrics,self).__init__()

        #Timer
        self.scheduler = sched.scheduler(time.time, time.sleep)
    
        # Probing attributes
        self.topology = None
        self.pendingResponses = None 


        # Policies, callbacks, etc
        self.query = packets()
        self.query.register_callback(self.printPack) 
        self.policy = mac_learner()
        self.floodPolicy = flood()
        self.dropPolicy = drop
        self.macLearner = mac_learner()
        self.metricsPolicy = None

    def sendPacket(self, sourceSwitch, outport, srcport):
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

    def updatePolicy(self):
        self.policy = if_(match(srcip = PROBEIP), self.metricsPolicy, self.macLearner)

    def printPack(self,pkt):
        print pkt 

    
    def probeAll(self):
        for switch in self.topology.nodes():
            sendProbes(switch)
  
    def sendProbes(self, switch):
        if self.topology:
                ports = [port for port in self.topology.node[switch]['ports']]
                for port in ports:
                    if self.topology.node[switch]['ports'][port].linked_to != None:
                            sendPacket(switch, port, switch+PORT_START) 
    

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
        
        metrics_policy = identity
        # We install a rule at each switch
        for node in network.topology.nodes():
            thisPolicy = identity
            for port in self.topology.node[node]['ports']:
                srcSwitch = self.topology.node[node]['ports'][port].linked_to
                if not srcSwitch == None:
                    srcSwitch= int(srcSwitch.switch)
                # If this switch received this probe packet from source (because the srcport probe matched), then flood it, otherwise drop it. In any case, query it. 
                    thisPolicy = thisPolicy + match(switch = node) >> if_(match(srcport=PORT_START+srcSwitch), self.floodPolicy, self.dropPolicy) 
            thisPolicy = match(switch=node) >> thisPolicy
            metrics_policy = metrics_policy + thisPolicy

        self.metricsPolicy = metrics_policy       
        self.updatePolicy()

        # restart the probing timer
        self.scheduler.empty()
#        self.scheduler.enter(5, 1, sayHello,())
 #       self.scheduler.run()
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

