Repository for the first homework of the Communication Networks class. In this homework the students will implement the dataplane of a router.

    Routing
When an IPv4 packet is received, its checkcum is checked. If it is bad, the packet is dropped. The packets is alse dropped if the ttl reaches 0 and an ICMP message is sent.
Then if the packet has the IP address of the interface it arrived through as its destination, it means its a ping request and is dealt with separetly.
Otherwise the packet is prepared for routing. The checksum is recalculated eith the decremented ttl.The best next hop is found using a trie tree. If there is no route to the destination in the route tree, an ICMP message is sent back.
If the mac of the next hop is not in the ARP cache, then the computed packet, its lenght and the interface it arrived through are saved and a ARP request is sent on broadcast.
If the next hop is in the ARP cache, the datagram is just sent.

    Longest prefix match
Each tree node contains 2 neighbours, next hop and its interface.
The trie tree is build using the prefix for each route. While the mask for that prefix isn's 0, we either go down the tree on a "0" direction or a "1" direction, based on the MSB of the prefix. At each step, both the prefix and the mask are shifted to the left, to compute the next bit as the MSB.
When the mask is 0, we realized a route in the tree that has the same "0" and "1" directions as the prefix and at that node we complete the next hop and interface.
When searching in the trie tree, we use the destination IP address to go at each node on a "0" or "1" route. The searched LPM is the last node with an initialized next hop and iterface that we traversed.

    ARP
During an IP packets computation, if we don't find the next hop's mac, the datagram, its lenght and iterface are saved in a queue and an ARP request is built and sent on the interface of the next hop with a broadcast hardware destination address.
When we recieve an ARP packet, it can be either a request or a repply:
If it is a request, the same packet is modified and acompleted so it becomes a reply and it is sent back to the hardware and IP adress it came from.
If it is a reply, the source IP and hardware adresses are saved in a cache and we iterate through all the datagrams in the queue. If the datagram's IP destination adress is the one that just arrived, just the destination mac is completed and the packet is sent. Otherwise, it is just requeued.

    ICMP
If we get a ping request, recognized as it is addressed to the interface it arrived through, the datagram is modifed to become a reply and its checksum is recalculated. Then the message is sent back to the IP and hardware adresses it came with originally.
If either we don't have a next hop for the current IP packet or the ttl reachess 0, new packet is built, with an ethernet, IP and ICMP header. In the ICMP payload the old packets IP header and 64 bytes of data are copied. The rest of the headers are completed and sent back with the destination IP and hardware adresses that the dropped packet came with as sources. The source adresses are the adresses of the interface the packet leaves through. Then the old packet is dropped.
