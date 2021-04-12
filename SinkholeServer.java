package il.ac.idc.cs.sinkhole;

import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.*;


public class SinkholeServer extends dnsR {
    // the original query that has been sent
    public static byte[] Query;
    // the original query length;
    public static int QLength;
    // the original query server
    public static InetAddress QServer;
    // the original query port
    public static int QPort;
    // the answer of the answer respond
    public static int ANLength;
    // the file name with the blocked domains
    public static String FileName = "blocklist.txt";

    /**
     *
     * @param dns
     * @return the first respond after it send the original query to the sever
     * @throws Exception
     */
    public static byte[] getFirstServer(dnsR dns) throws Exception {

        // Receive the first query from dig
        DatagramPacket dataPacket = dns.serverSocket.received();
        // getting the data from the Datagram packet
        HashSet<String> blockList = getBlockList(FileName);
        Query = dataPacket.getData();
        QLength = dataPacket.getLength();
        Query = Arrays.copyOfRange(Query,0, QLength);
        QServer = dataPacket.getAddress();
        QPort = dataPacket.getPort();
        getName(Query,12);
        clearDomain();
        for (String url: blockList
        ) {
            if(url.compareTo(getServer()) == 0){
                Query[2] = (byte)0b10000000;
                Query[3] = (byte)0b00000011;
                DatagramPacket sendPacketToRoot = new DatagramPacket(Query, QLength, QServer, QPort);
                // DatagramSocket rootServer = new DatagramSocket();
                dns.serverSocket.socket.send(sendPacketToRoot);
                return null;
            }
        }
        // get a random server from the 13 root server's list
        String rootServerIp = randomRootServer();
        //TODO: check if the domain is in the block list

        // send the query to the choosen root server
        return SendAndReceive(Query, rootServerIp);

    }

    /**
     *
     * @param bArray - the packet we want to send
     * @param server - to which server we want to send
     * @return
     * @throws IOException
     */
    private static byte[] SendAndReceive(byte[] bArray, String server) throws IOException {
        DatagramPacket sendPacketToRoot = new DatagramPacket(bArray, QLength,
                InetAddress.getByName(server), 53);
        DatagramSocket rootServer = new DatagramSocket();
        rootServer.send(sendPacketToRoot);
        byte[] receiveData = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(receiveData,
                receiveData.length);
        rootServer.receive(receivePacket);
        bArray = receivePacket.getData();
        ANLength = receivePacket.getLength();
//        System.out.println(bArray.length);
        return bArray;
    }

    /**
     *
     * @param FileName the file name of the blocked list
     * @return return a hash set with all the blocked servers
     * @throws IOException
     */
    public static HashSet<String> getBlockList(String FileName) throws IOException {
        HashSet<String> blockList = new HashSet<>();
        String strCurrentLine;
        try {
            BufferedReader objReader = new BufferedReader(new FileReader(FileName));
            while ((strCurrentLine = objReader.readLine()) != null) {
                blockList.add(strCurrentLine);
            }

        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
        return blockList;
    }
    public static void main(String[] args) throws Exception {
        while (true){

            //open a listening socket on port 5300
            dnsR dns = new dnsR();
            // get the first respond from the server
            byte[] bArray = getFirstServer(dns);
            //  if the domain is blocked it return null and stop the program
            if (bArray == null) {
                System.out.println("Blocked Server");
                return;
            }
            // get the header of the respond
            getHeader(bArray, bArray.length);


            // limit the number of iterations to 16

            // check for the next server in the respond
            while (getRCODE().equals("0000") && getANCOUNT() == 0 && getNSCOUNT() > 0) {
                // get the domain name
                int y = getName(bArray, 12);
                // get the type, class, RDLENGTH and TTL if needs to
                int y1 = getAuth(bArray, y);
                // clear the domain name in list
                clearDomain();
                // checks if the NSCOUNT is greater than 0
                if (getNSCOUNT() > 0) {
                    // gets the domain name from the first authority
                    int z = getName(bArray, y1);
                    // get the type, class, RDLENGTH and TTL from the first authority
                    int z1 = getAuth(bArray, z);
                    clearDomain();
                    // get the first server
                    int x = getName(bArray, z1);
                    String server = getServer();
                    System.out.println("server " + server);

                    bArray = SendAndReceive(Query, server);
                    getHeader(bArray, bArray.length);
                    clearDomain();

//
                }

            }
            HashMap<Integer, String> Errors = new HashMap<>();
            Errors.put(1, "Format error - The name server was unable to interpret the query.");
            Errors.put(2, "Server failure - The name server was unable to process this query due to a problem with the name server");
            Errors.put(3, "Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.");
            Errors.put(4, "Not Implemented - The name server does not support the requested kind of query.");
            Errors.put(5, "Refused - The name server refuses to perform the specified operation for policy reasons");


            if (!getRCODE().equals("0000")) {
                int RCode = bArray[3] & 0b1111;
                DatagramPacket sendPacketToRoot = new DatagramPacket(bArray, ANLength, QServer, QPort);
                dns.serverSocket.socket.send(sendPacketToRoot);
                System.out.println("err");
                System.out.println("RCode " + RCode);
                System.err.println(Errors.get(RCode));
                dns.serverSocket.socket.close();

            }
            else if (getANCOUNT() == 1) {
                p("ID is 0x" + byteToHex(bArray, 0, 2));
                bArray[2] = (byte) 0b10000001;
                bArray[3] = (byte) 0b10000000;
                DatagramPacket sendPacketToRoot = new DatagramPacket(bArray, ANLength, QServer, QPort);
                dns.serverSocket.socket.send(sendPacketToRoot);
                System.out.println("success");

                bArray = getFirstServer(dns);
                if (bArray != null) {
                    getHeader(bArray, bArray.length);
                }
                //return;
            }
            dns.serverSocket.socket.close();

        }

    }


}
