# Prolog-FireWall
Contains some of the code used to build a project in Prolog to build FireWall rules as part of the course "Logic In Computer Science"

## Gist
So the aim of this project was to develop FireWall rules according to https://www.ibm.com/support/knowledgecenter/en/SSETBF_3.1.1/com.ibm.siteprotector.doc/references/pam_filter_sets.html, encoded in the programming language *SWI-Prolog*.

Prolog is an old language that enforces Hoare's rules on every statement. Everything is constructed from Conjunctions and Predicates. The model uses Predicate Logic to define predicates, which in turn, use Conjunctions and/or Recursion, to achieve the desired task.

## Evaluation of a given Query with the rules constructed
Suppose the Adapter 'A', accepts all packets to the adapter, adn Adapter 'B' rejects all incoming packets toward the respective port, check('B', _ ) returns False, where the symbol '_' is used to define a wildcard.

There are multiple layers of Firewall checks. If the adapter chosen is 'A', it then tries to move on to the next field on the datagram provided by rhe packet. (For example, the TCP Ports). Now, if the TCP source and destination ports do not match with what we already know, we reject that specific range of TCP ports. For the TCP connection to be accepted, we must have both the source and the destination ports as valid, given in the database, along with the other conditions being accepted as well (like the Adapter condition).

The program checks for all kinds of queries on the Packet Datagram when it enters the system, essentially forming what is called a FireWall for the system. 
