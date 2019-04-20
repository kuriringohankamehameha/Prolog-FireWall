sum(X,0,X).

sum(X,Y,Z):- A is X+1, B is Y-1, sum(A,B,Z).

adapter(X):-random_member(Y,['A','B','C']),adapter(Y,X).
adapter('A','Accept').
adapter('B','Reject').
adapter('C','Drop').
adapter(Y,'Reject'):- \+(adapter(Y,'Accept')), \+(adapter(Y,'Drop')), write('Adapter invalid.').

check(Ad,Eth,Ipv4,Ipv6,TcpCmdList,UdpCmdList,X)  :- adapter(Ad,A), ether_check(Eth,E), is_list(Ipv4), ipv4(Ipv4,I4), is_list(Ipv6), ipv6(Ipv6,I6), tcp(TcpCmdList,T), udp(UdpCmdList,U),cond(A,E,I4,I6,T,U,X).

%Protocol Type of IPV4/6 needs to be passed to ICMP to return a message

%check(Adapter, [VLAN,Prototype], [Source_Address, Destination_Address], [TCP_Source_Port, %TCP_Destination_Port], [UDP_Source_Port, UDP_Destination_Port], [Protocol_Type, Message_Code]

cond(A,E,I4,I6,T,U,'Accept') :- A='Accept', E='Accept', I4='Accept', I6='Accept', T='Accept',U='Accept'.
cond(A,E,I4,I6,T,U,'Reject') :- A='Reject'; E='Reject'; I4='Reject'; I6='Reject'; T='Reject'; U='Reject'.
cond(A,E,I4,I6,T,U,'Drop') :- (A='Drop'; E='Drop'; I4='Drop'; I6='Drop'; T='Drop'; U='Drop'), \+(A='Reject'; E='Reject'; I4='Reject'; I6='Reject'; T='Reject';U='Reject').


ethernet('dst','100','Accept').


ipv4(T,Is) :- is_list(T),length(T,4), nth0(1,T,'src'), nth0(3,T,IpElem), srcv4(IpElem,Is).
ipv4(T,Is) :- is_list(T),length(T,4), nth0(1,T,'dst'), nth0(3,T,IpElem), dstv4(IpElem,Is).
ipv4(T,Is) :- is_list(T),length(T,3), nth0(1,T,'addr'), nth0(2,T,IpElem), addrv4(IpElem,Is).
ipv4(T,Is) :- is_list(T),length(T,3), nth0(1,T,'proto'), nth0(2,T,IpElem), protov4(IpElem,Is).
ipv4(T,Is) :- is_list(T),length(T,7), nth0(1,T,'src'), nth0(3,T,IpElem1), srcv4(IpElem1,Is), 
                           nth0(4,T,'dst'), nth0(6,T,IpElem2), dstv4(IpElem2,Is).
ipv4(T,'Drop') :- is_list(T),length(T,7), nth0(1,T,'src'), nth0(3,T,IpElem1),
                           nth0(4,T,'dst'), nth0(6,T,IpElem2), (srcv4(IpElem1,'Drop'); dstv4(IpElem2,'Drop')).
ipv4(T,Is) :- is_list(T),length(T,9), nth0(1,T,'src'), nth0(3,T,IpElem1), srcv4(IpElem1,Is),
                           nth0(4,T,'dst'), nth0(6,T,IpElem2), dstv4(IpElem2,Is),
                           nth0(7,T,'proto'), nth0(8,T,IpElem3), protov4(IpElem3,Is).
ipv4(T,'Drop') :- is_list(T),length(T,9), nth0(1,T,'src'), nth0(3,T,IpElem1),
                           nth0(4,T,'dst'), nth0(6,T,IpElem2), 
                           nth0(7,T,'proto'), nth0(8,T,IpElem3), (srcv4(IpElem1,'Drop'); dstv4(IpElem2,'Drop'); protov4(IpElem3,'Drop')).
ipv4(T,'Reject') :- (\+(ipv4(T,'Accept')), \+(ipv4(T,'Drop'))), write('IPV4 invalid.').

ipv6(T,Is2) :- is_list(T),length(T,4), nth0(1,T,'src'), nth0(3,T,IpElem), srcv6(IpElem,Is2).
ipv6(T,Is2) :- is_list(T),length(T,4), nth0(1,T,'dst'), nth0(3,T,IpElem), dstv6(IpElem,Is2).
ipv6(T,Is2) :- is_list(T),length(T,3), nth0(1,T,'addr'), nth0(2,T,IpElem), addrv6(IpElem,Is2).
ipv6(T,Is2) :- is_list(T),length(T,3), nth0(1,T,'proto'), nth0(2,T,IpElem), protov6(IpElem,Is2).
ipv6(T,Is2) :- is_list(T),length(T,7), nth0(1,T,'src'), nth0(3,T,IpElem1), srcv6(IpElem1,Is2), 
                           nth0(4,T,'dst'), nth0(6,T,IpElem2), dstv6(IpElem2,Is2).
ipv6(T,'Drop') :- is_list(T),length(T,7), nth0(1,T,'src'), nth0(3,T,IpElem1),
                           nth0(4,T,'dst'), nth0(6,T,IpElem2), (srcv6(IpElem1,'Drop'); dstv6(IpElem2,'Drop')).
ipv6(T,Is2) :- is_list(T),length(T,9), nth0(1,T,'src'), nth0(3,T,IpElem1), srcv6(IpElem1,Is2), 
                           nth0(4,T,'dst'), nth0(6,T,IpElem2), dstv6(IpElem2,Is2),
                           nth0(7,T,'proto'), nth0(8,T,IpElem3), protov6(IpElem3,Is2).
ipv6(T,'Drop') :- is_list(T),length(T,9), nth0(1,T,'src'), nth0(3,T,IpElem1),
                           nth0(4,T,'dst'), nth0(6,T,IpElem2), 
                           nth0(7,T,'proto'), nth0(8,T,IpElem3), (srcv6(IpElem1,'Drop'); dstv6(IpElem2,'Drop'); protov6(IpElem3,'Drop')).
ipv6(T,'Reject') :- (\+(ipv6(T,'Accept')), \+(ipv6(T,'Drop'))), write('IPV6 invalid.').

%TCP Conditions

tcp_compare(A,B,'Accept'):-A='Accept',B='Accept'.
tcp_compare(A,B,'Reject'):- A='Reject';B='Reject'.
tcp_compare(A,B,'Drop'):-A='Drop';B='Drop'.

tcp2(Dst,'Reject'):-tcp_ports(A,B,'Reject'),(A<Dst;A=Dst),(B>Dst;B=Dst).
tcp2(Dst,'Accept'):-tcp_ports(A,B,'Accept'),(A<Dst;A=Dst),(B>Dst;B=Dst).
tcp2(Dst,'Drop'):-tcp_ports(A,B,'Drop'),(A<Dst;A=Dst),(B>Dst;B=Dst).

%Double Ranges for TCP
tcprange(Dst,Src,'Reject'):-tcp_ports(Dst1,Dst2,A,B,'Reject'),(A<Src;A=Src),(B>Src;B=Src),(Dst1<Dst;Dst1=Dst),(Dst2>Dst;Dst2=Dst).
tcprange(Dst,Src,'Accept'):-tcp_ports(Dst1,Dst2,A,B,'Accept'),(A<Src;A=Src),(B>Src;B=Src),(Dst1<Dst;Dst1=Dst),(Dst2>Dst;Dst2=Dst).
tcprange(Dst,Src,'Drop'):-tcp_ports(Dst1,Dst2,A,B,'Drop'),(A<Src;A=Src),(B>Src;B=Src),(Dst1<Dst;Dst1=Dst),(Dst2>Dst;Dst2=Dst).
tcprange(Dst,Src,'Accept').



tcp3(Dst,Src,'Reject'):-tcp_ports(Dst,A,B,'Reject'),(A<Src;A=Src),(B>Src;B=Src).
tcp3(Dst,Src,'Accept'):-tcp_ports(Dst,A,B,'Accept'),(A<Src;A=Src),(B>Src;B=Src).
tcp3(Dst,Src,'Drop'):-tcp_ports(Dst,A,B,'Drop'),(A<Src;A=Src),(B>Src;B=Src).


tcp6(A,B,'Reject'):-tcp_ports(Src,Dst,'Reject'),is_list(Src),is_list(Dst),(member(Src,A,Z),member(Dst,B,Z)).
tcp6(A,B,'Drop'):-tcp_ports(Src,Dst,'Drop'),is_list(Src),is_list(Dst),member(Dst,B,Z),(member(Src,A,Z)).
tcp6(A,B,'Accept'):-tcp_ports(Src,Dst,'Accept'),is_list(Src),is_list(Dst),member(Dst,B,Z),member(Src,A,Z).

tcp4(A,B,'Reject'):-tcp_ports(A,Dst,'Reject'),is_list(Dst),member(Dst,B,Z).
tcp4(A,B,'Drop'):-tcp_ports(A,Dst,'Drop'),is_list(Dst),member(Dst,B,Z).
tcp4(A,B,'Accept'):-tcp_ports(A,Dst,'Accept'),is_list(Dst),member(Dst,B,Z).

tcp5(B,'Reject'):-tcp_ports(Dst,'Reject'),is_list(Dst),member(Dst,B,Z).
tcp5(B,'Drop'):-tcp_ports(Dst,'Drop'),is_list(Dst),member(Dst,B,Z).
tcp5(B,'Accept'):-tcp_ports(Dst,'Accept'),is_list(Dst),member(Dst,B,Z).




%THis is fine(orig))
tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1),nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2),tcp6(Port1,Port2,Answer).

tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1),nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2),tcp4(Port1,Port2,Answer).

tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1), dst_port(Port1,Answer1),Answer1='Reject',nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2), tcp_src_port(Port2,Answer),Answer='Reject',write("tcp destination and source ports Invalid. "),nl.
tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1), tcp_dst_port(Port1,Answer),(Answer='Reject',write("tcp destination port Invalid. ")),nl.
tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2), tcp_src_port(Port2,Answer),Answer='Reject',write("tcp source port Invalid. "),nl.

tcp(TcpCmdList,Answer):- length(TcpCmdList,4), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'src'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port), tcp_src_port(Port,Answer),(Answer='Reject',write("tcp source port Invalid. ")),nl.
tcp(TcpCmdList,Answer):- length(TcpCmdList,4), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port), tcp_dst_port(Port,Answer),(Answer='Reject',write("tcp destination port Invalid. ")),nl.

/*
tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1), dst_port(Port1,Answer1),Answer1='Drop',nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2), tcp_src_port(Port2,Answer).
tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1), tcp_dst_port(Port1,Answer).
tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2), tcp_src_port(Port2,Answer).

tcp(TcpCmdList,Answer):- length(TcpCmdList,4), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'src'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port), tcp_src_port(Port,Answer).
tcp(TcpCmdList,Answer):- length(TcpCmdList,4), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port), tcp_dst_port(Port,Answer).
*/


tcp(TcpCmdList,Answer):- length(TcpCmdList,4), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'src'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port), tcp_src_port(Port,Answer).

tcp(TcpCmdList,Answer):- length(TcpCmdList,4), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port), tcp2(Port,Answer).

tcp(TcpCmdList,Answer):- length(TcpCmdList,4), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port), tcp5(Port,Answer).



tcp(TcpCmdList,Answer):- length(TcpCmdList,4), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port), tcp_dst_port(Port,Answer).

tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1),nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2),tcp3(Port1,Port2,Answer).

tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1),nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2),tcprange(Port1,Port2,Answer).

tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1), tcp_dst_port(Port1,Answer1),nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2), tcp_src_port(Port2,Answer2),tcp_compare(Answer1,Answer2,Answer).

tcp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'tcp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1), dst_port(Port1,Answer1),\+(Answer1='Reject'),nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2), tcp_src_port(Port2,Answer).

tcp(TcpCmdList,'Accept').

%UDP Conditions
udp_compare(A,B,'Accept'):-A='Accept',B='Accept'.
udp_compare(A,B,'Reject'):- A='Reject';B='Reject'.
udp_compare(A,B,'Drop'):-A='Drop';B='Drop'.

udprange(Dst,Src,'Reject'):-udp_ports(Dst1,Dst2,A,B,'Reject'),(A<Src;A=Src),(B>Src;B=Src),(Dst1<Dst;Dst1=Dst),(Dst2>Dst;Dst2=Dst).
udprange(Dst,Src,'Accept'):-udp_ports(Dst1,Dst2,A,B,'Accept'),(A<Src;A=Src),(B>Src;B=Src),(Dst1<Dst;Dst1=Dst),(Dst2>Dst;Dst2=Dst).
udprange(Dst,Src,'Drop'):-udp_ports(Dst1,Dst2,A,B,'Drop'),(A<Src;A=Src),(B>Src;B=Src),(Dst1<Dst;Dst1=Dst),(Dst2>Dst;Dst2=Dst).
udprange(Dst,Src,'Accept').


udp2(Dst,'Reject'):-udp_ports(A,B,'Reject'),(A<Dst;A=Dst),(B>Dst;B=Dst).
udp2(Dst,'Accept'):-udp_ports(A,B,'Accept'),(A<Dst;A=Dst),(B>Dst;B=Dst).
udp2(Dst,'Drop'):-udp_ports(A,B,'Drop'),(A<Dst;A=Dst),(B>Dst;B=Dst).

udp3(Dst,Src,'Reject'):-udp_ports(Dst,A,B,'Reject'),(A<Src;A=Src),(B>Src;B=Src).
udp3(Dst,Src,'Accept'):-udp_ports(Dst,A,B,'Accept'),(A<Src;A=Src),(B>Src;B=Src).
udp3(Dst,Src,'Drop'):-udp_ports(Dst,A,B,'Drop'),(A<Src;A=Src),(B>Src;B=Src).


udp6(A,B,'Reject'):-udp_ports(Src,Dst,'Reject'),is_list(Src),is_list(Dst),(member(Src,A,Z),member(Dst,B,Z)).
udp6(A,B,'Drop'):-udp_ports(Src,Dst,'Drop'),is_list(Src),is_list(Dst),member(Dst,B,Z),(member(Src,A,Z)).
udp6(A,B,'Accept'):-udp_ports(Src,Dst,'Accept'),is_list(Src),is_list(Dst),member(Dst,B,Z),member(Src,A,Z).


udp4(A,B,'Reject'):-udp_ports(A,Dst,'Reject'),is_list(Dst),member(Dst,B,Z).
udp4(A,B,'Drop'):-udp_ports(A,Dst,'Drop'),is_list(Dst),member(Dst,B,Z).
udp4(A,B,'Accept'):-udp_ports(A,Dst,'Accept'),is_list(Dst),member(Dst,B,Z).

udp5(B,'Reject'):-udp_ports(Dst,'Reject'),is_list(Dst),member(Dst,B,Z).
udp5(B,'Drop'):-udp_ports(Dst,'Drop'),is_list(Dst),member(Dst,B,Z).
udp5(B,'Accept'):-udp_ports(Dst,'Accept'),is_list(Dst),member(Dst,B,Z).


udp(UdpCmdList,Answer):- length(UdpCmdList,7), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port1),nth0(4,UdpCmdList,'src'),nth0(6,UdpCmdList,Port2),udp6(Port1,Port2,Answer).

udp(UdpCmdList,Answer):- length(UdpCmdList,7), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port1),nth0(4,UdpCmdList,'src'),nth0(6,UdpCmdList,Port2),udp4(Port1,Port2,Answer).

udp(UdpCmdList,Answer):- length(UdpCmdList,7), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port1), dst_port(Port1,Answer1),Answer1='Reject',nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2), udp_src_port(Port2,Answer),Answer='Reject',write("udp destination and source ports Invalid. "),nl.
udp(UdpCmdList,Answer):- length(UdpCmdList,7), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port1), udp_dst_port(Port1,Answer),(Answer='Reject',write("udp destination port Invalid. ")),nl.
udp(UdpCmdList,Answer):- length(UdpCmdList,7), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(4,UdpCmdList,'src'),nth0(6,UdpCmdList,Port2), udp_src_port(Port2,Answer),Answer='Reject',write("udp source port Invalid. "),nl.

udp(UdpCmdList,Answer):- length(UdpCmdList,4), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'src'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port), udp_src_port(Port,Answer),(Answer='Reject',write("udp source port Invalid. ")),nl.
udp(UdpCmdList,Answer):- length(UdpCmdList,4), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'src'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port), udp_src_port(Port,Answer),Answer='Reject',write("udp source port Invalid. "),nl.
udp(UdpCmdList,Answer):- length(UdpCmdList,4), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port), udp_dst_port(Port,Answer),(Answer='Reject',write("udp destination port Invalid. ")),nl.


udp(UdpCmdList,Answer):- length(UdpCmdList,4), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'src'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port), udp_src_port(Port,Answer).

udp(UdpCmdList,Answer):- length(UdpCmdList,4), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port), udp2(Port,Answer).


udp(UdpCmdList,Answer):- length(UdpCmdList,4), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port), udp5(Port,Answer).


udp(UdpCmdList,Answer):- length(UdpCmdList,4), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port), udp_dst_port(Port,Answer).

udp(UdpCmdList,Answer):- length(UdpCmdList,7), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port1),nth0(4,UdpCmdList,'src'),nth0(6,UdpCmdList,Port2),(udp3(Port1,Port2,Answer)).

udp(UdpCmdList,Answer):- length(UdpCmdList,7), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port1),nth0(4,UdpCmdList,'src'),nth0(6,UdpCmdList,Port2),udprange(Port1,Port2,Answer).


udp(TcpCmdList,Answer):- length(TcpCmdList,7), nth0(0,TcpCmdList,'udp'), nth0(1,TcpCmdList,'dst'), nth0(2,TcpCmdList,'port'),nth0(3,TcpCmdList,Port1), udp_dst_port(Port1,Answer1),nth0(4,TcpCmdList,'src'),nth0(6,TcpCmdList,Port2), udp_src_port(Port2,Answer2),udp_compare(Answer1,Answer2,Answer).

udp(UdpCmdList,Answer):- length(UdpCmdList,7), nth0(0,UdpCmdList,'udp'), nth0(1,UdpCmdList,'dst'), nth0(2,UdpCmdList,'port'),nth0(3,UdpCmdList,Port1), udp_dst_port(Port1,Answer1),\+(Answer1='Reject'), nth0(4,UdpCmdList,'src'),nth0(6,UdpCmdList,Port2), udp_src_port(Port2,Answer).

udp(UdpCmdList,'Accept').



srcv4('108','Reject').
dstv4('108','Reject').
addrv4('108','Reject').
protov4('specific','Reject').

srcv6('1008','Accept').
dstv6('1008','Accept').
addrv6('108','Reject').
protov6('specific','Accept').

%tcp_ports(Destination_Address,Source_Address).
tcp_ports(220,'Accept').
tcp_ports(200,500,'Accept').
tcp_ports(100,[401,420],'Drop').
tcp_ports([8,9],[401,420],'Reject').
tcp_ports(125,250,275,'Accept').
tcp_ports(225,350,375,'Reject').
tcp_ports(5000,5050,5000,5070,'Drop').

udp_ports(100,[401,420],'Accept').
udp_ports(200,500,'Accept').
udp_ports([8,9],[401,420],'Reject').
udp_ports(125,250,275,'Accept').
udp_ports(5000,5050,5000,5070,'Drop').


tcp_src_port('any','Accept').
tcp_src_port(570,'Accept').
tcp_src_port(601,'Reject').
tcp_src_port(5007,'Accept').
tcp_src_port(500,600,'Reject').

tcp_dst_port(5007,'Accept').
tcp_dst_port(600,'Reject').
tcp_dst_port('any','Accept').
tcp_dst_port(540,'Drop').

udp_src_port(601,'Reject').
udp_dst_port(600,'Reject').

vid(875,'Reject').

proto_eth('any','Accept').
proto_eth(180,'Reject').

%Here, proto_eth has both vid as well as Proto_ID
proto_eth(1,0x0800,'Reject').
proto_eth(2,0x86dd,'Reject').
proto_eth(1,-1,'Accept').
proto_eth(4,69,'Drop').
proto_eth(20,1000,'Reject').
proto_eth(21,1000,'Drop').
proto_eth(22,1000,'Reject').
proto_eth(23,1000,'Accept').
proto_eth([30,40],[2045,2046],'Reject').

member([A|_],A,_).
member([H|T],A,Z):- \+(H=A),member(T,A,Z).

member1(Orig,[],_,_).
member1(Orig,[],[R|S],Z):-member1(Orig,Orig,S,Z).
member1(Orig,[P|Q],[R|S],Z):- \+(P=R),member1(Orig,Q,[R|S],Z).

proto_eth3(A,B,'Reject'):-proto_eth(VLAN_ID,Proto_ID,'Reject'),is_list(VLAN_ID),is_list(Proto_ID),member(VLAN_ID,A,Z),member(Proto_ID,B,Y).
proto_eth3(A,B,'Accept'):-proto_eth(VLAN_ID,Proto_ID,'Accept'),is_list(VLAN_ID),is_list(Proto_ID),member(VLAN_ID,A,Z),member(Proto_ID,B,Y).

proto_eth2(VLAN,Proto_ID,'Reject'):-proto_eth(A,B,Proto_ID,'Reject'),(A<VLAN;A=VLAN),(B>VLAN;B=VLAN).
proto_eth2(VLAN,Proto_ID,'Accept'):-proto_eth(A,B,Proto_ID,'Accept'),(A<VLAN;A=VLAN),(B>VLAN;B=VLAN).
proto_eth2(VLAN,Proto_ID,'Drop'):-proto_eth(A,B,Proto_ID,'Drop'),(A<VLAN;A=VLAN),(B>VLAN;B=VLAN).

%Here, proto_eth is of the format proto_eth(VLAN_ID_Start,VLAN_ID_End,Proto_ID,Z).
proto_eth(10,20,2044,'Reject').
proto_eth(10,20,2054,'Accept').


proto_eth(A,A,Proto_ID,Z):-proto_eth(A,Proto_ID,'Reject'),write(A),write(" is rejected"),nl;proto_eth(A,Proto_ID,'Accept'),write(A),write(" is accepted"),nl;proto_eth(A,Proto_ID,'Drop').

proto_eth(Start,End,Proto_ID,Z):-proto_eth(Start,Proto_ID,Z),Z='Reject',write(Start),write(" rejected"),nl,A is Start+1,proto_eth(A,End,Proto_ID,Z).

proto_eth(Start,End,Proto_ID,Z):-proto_eth(Start,Proto_ID,Z),Z='Accept',write(Start),write(" accepted"),nl,A is Start+1,proto_eth(A,End,Proto_ID,Z).

proto_eth(Start,End,Proto_ID,Z):-proto_eth(Start,Proto_ID,Z),write(Start),write(" is not there, so dropped"),nl,A is Start+1,proto_eth(A,End,Proto_ID,Z).

list_check(Start,End,[],Z).
list_check(Start,End,[A|B],Z):-proto_eth(Start,End,A,Z),list_check(Start,End,B,Z).

ether_check(EthList,Z):-is_list(EthList),length(EthList,3),nth0(1,EthList,'proto'),nth0(2,EthList,M),proto_eth(M,Z),Z='Reject',write("Ethernet Protocol blocked. ").

ether_check(EthList,Z):-is_list(EthList),length(EthList,3),nth0(1,EthList,'proto'),nth0(2,EthList,M),proto_eth(M,Z).

ether_check(EthList,Z):-is_list(EthList),length(EthList,3),nth0(1,EthList,'vid'),nth0(2,EthList,M),vid(M,Z),Z='Reject',write("Ethernet VLAN blocked. ").
ether_check(EthList,Z):-is_list(EthList),length(EthList,3),nth0(1,EthList,'vid'),nth0(2,EthList,M),vid(M,Z).

ether_check(EthList,Z):-is_list(EthList),length(EthList,5),nth0(1,EthList,'vid'),nth0(3,EthList,'proto'),nth0(2,EthList,A),nth0(4,EthList,Proto_ID),(proto_eth2(A,Proto_ID,Z)),write("Ethernet check done for the range(no) query!!").

ether_check(EthList,Z):-is_list(EthList),length(EthList,5),nth0(1,EthList,'vid'),nth0(3,EthList,'proto'),nth0(2,EthList,A),nth0(4,EthList,Proto_ID),(proto_eth3(A,Proto_ID,Z)),write("Ethernet check done for the list query!!").

ether_check(EthList,Z):-is_list(EthList),length(EthList,5),nth0(1,EthList,'vid'),nth0(3,EthList,'proto'),nth0(2,EthList,VLAN),nth0(4,EthList,Proto_ID),(proto_eth(VLAN,Proto_ID,'Reject'));(vid(VLAN,'Reject'));proto_eth(Proto_ID,'Reject'),Z='Reject',write("Ethernet is blocked !!").

ether_check(EthList,Z):-is_list(EthList),length(EthList,5),nth0(1,EthList,'vid'),nth0(3,EthList,'proto'),nth0(2,EthList,VLAN),nth0(4,EthList,Proto_ID),(proto_eth(Proto_ID,'Accept')),Z='Accept'.

ether_check(EthList,Z):-is_list(EthList),length(EthList,5),nth0(1,EthList,'vid'),nth0(3,EthList,'proto'),nth0(2,EthList,VLAN),nth0(4,EthList,Proto_ID),(proto_eth(VLAN,Proto_ID,'Drop')),Z='Drop'.

ether_check(EthList,_):-(\+(is_list(EthList));\+(length(EthList,3);length(EthList,5))),write("Ethernet Invalid").

ether_check(EthList,'Accept').



