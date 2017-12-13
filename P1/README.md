UCLA CS118 Project 1 (Simple Router)
====================================

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## Report
Name: Bach Hoang
UID: 104737449

# Design
- SimpleRouter::handlePacket()
+ Sanity check the received packet
+ Read ethernet header as well as well as packet type
    . If packet is ARP, pass ARP header to handleArpPacket()
    . If packet is IP, pass IP header and payload to handleIpPacket()

- SimpleRouter::handleArpPacket()
+ Read opcode to decide the type of ARP packet
    . If ARP packet is a request, create a new Buffer as a reply, fill in the fields and send it
    . If ARP packet is a reply, insert an ARP entry with the new IP-MAC mapping, send enqueued packets that were waiting for the reply and remove that queue

- SimpleRouter::handleIpPacket()
+ Verify checksum and check if the packet is destined to this router (destination ip is one of the ip of this router)
    . If the packet is to this router, ignore
    . If the packet is to be forwarded
        .. Decrement TTL and recalculate checksum
        .. Find next hop IP addr and look that addr up
            ... If found an entry for next hop IP addr, send packet there
            ... If found no entry, queue the packet and send and ARP request (if one hasn't been sent)

- RoutingTable::maskLength(): a helper for lookup() that calculate the length of a mask by bit-wise ANDing every bits of mask with 1

- RoutingTableEntry RoutingTable::lookup(): check if given ip addr matches a ip addr in the routing table while keeping track of the longest mask length so far

# Difficulties
                What                                                                                                 Solved how
- Understanding what to do (when to send, send to where,...)                                            - Read the specs, lecture notes
- Be familiar the skeleton code (what function do what, where to use ntohs and htons,...)               - Spend time on it!!!