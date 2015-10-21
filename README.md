# CPEN442-VPN

To run this locally, open two terminals. In one, do:  
    python vpn.py  
In the other, do:  
    python client.py  
	
	
	
To run the java: 
1) double click and open two instances of the jar file (it is an executable)  

2) on the first one, configure as needed and then click start connection 

3) on the second one, configure to be the same as server then click on client before starting connection 

4) instructions stop at each step, click continue to move on to the next step 

5) when both windows says "Connection confirmed", meessagse can now be sent from client to server 

6) to send message, type in data to send and press enter 

7) messages should appear in data as received window on server 


note 1: server must start connection first, otherwise client will fail because it cannot find server's port 
note 2: timestamp (used as a nonce) is set to expire after 1 minute, so authentication will fail if you wait a 
minute before pressing continue 

