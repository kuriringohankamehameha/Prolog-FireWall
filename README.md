# Prolog-FireWall
Contains some of the code used to for a project in Prolog to build FireWall rules as part of the course "Logic In Computer Science"

## Gist
So the aim of this project was to develop FireWall rules according to https://www.ibm.com/support/knowledgecenter/en/SSETBF_3.1.1/com.ibm.siteprotector.doc/references/pam_filter_sets.html, encoded in the programming language *SWI-Prolog*.

Prolog is an old language that enforces Hoare's rules on every statement. Everything is constructed from Conjunctions and Predicates. The model uses Predicate Logic to define predicates, which in turn, use Conjunctions and/or Recursion, to achieve the desired task.

## Evaluation of a given Query with the rules constructed
Suppose the Adapter 'A', accepts all packets to the adapter, and Adapter 'B' rejects all incoming packets toward the respective port, check('B', _ ) returns False, where the symbol '_' is used to define a wildcard. That is, check('B', anything_else) == False

We check multiple rules in the FireWall, to ensure that the packet is valied before it is finally allowed to pass through the Firewall; starting from the Adapter clause. Next, we construct similar predicates for checking Ethernet, TCP, UDP, IPv4 and IPv6 conditions. Only if the packet passes all these conditions, will it finally get accepted through the Firewall. Otherwise, it either gets *Dropped*, or *Rejected*, and the corresponding message is shown, as a condition is violated.

## Example
Given that the database has:
* Adapter('A', 'Accept').
* proto_eth(10,20,2054,'Accept').

Here, proto_eth predicate takes the arguments **proto_eth(VLAN_ID_Start, VLAN_ID_End, Proto_ID, Z)**, where Z is the output;
which means that it contains the list of VLAN_IDs for a particular Protocol ID for which the packet is Accepted, Dropped or Rejected, onto the next level.

This means that any packet having *both* Adapter='A' and proto_eth(vid,2054,Z) will be Accepted (Z='Accept') only if vid is between 10 and 20, as per the rules in the database.

(Here, 'vid' means VLAN ID, and 'proto' means PROTO_ID)
Hence, Check('A',['vid',12,'proto',2054]) is *Accepted* by the firewall for the Adapter and Ethernet clauses

There are multiple layers of Firewall checks. If the adapter chosen is 'A', it then tries to move on to the next field on the datagram provided by rhe packet. (For example, the TCP Ports). Now, if the TCP source and destination ports do not match with what we already know, we reject that specific range of TCP ports. For the TCP connection to be accepted, we must have both the source and the destination ports as valid, given in the database, along with the other conditions being accepted as well (like the Adapter condition).

The program checks for all kinds of queries on the Packet Datagram when it enters the system, essentially forming what is called a FireWall for the system. 
