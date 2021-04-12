the program iteratively resolves any request for domains not included in that block-list.

dnsR - a Helper class that takes the respond packet and resolve it to its parts, by getting the header,
that domain name, class type, and server name. also the class is respansable for almost all the function
we need on bytes, to get the right format for the respond we want to send
SinkholeServer - a class with the main function, also it has a function that create the first connection
and saves the first query in a global variable, so we can use is to respond to the client

UDPServer - a class with a socket as a proberty, and the constructor sends and recieve the first query
from the random server.

SinkholeServer - the main class of the program that runs the server that listens on port 5300 for anu DNS
query, and respond by returning the DNS server. also in the class, we have the sending and receiving the
packets to the servers and getting the respond packet that we need to resolve.
we handle the errors of the DNS RCode by returning an suitable error throw the System.err.printf