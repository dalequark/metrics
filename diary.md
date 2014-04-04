4/2/14:
- In the packet, the update is going to look like this:
IP,


- This is how it's going to work. Every host runs a python program thatover some set interval sends traceroutes to all other hosts in the network (How does it know which hosts exist actually?). This allows
it to get a measurement on the ingoing connection from it to other hosts. It then a compiles and sends this table to the controller. 
