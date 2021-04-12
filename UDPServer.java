package il.ac.idc.cs.sinkhole;/*
    from the course book:  Computer Networking: A Top Down Approach, by Kurose and Ross
 */
import java.io.IOException;
import java.net.*;
import java.util.Arrays;

class UDPServer
{
    DatagramSocket socket;
    int port;
    public UDPServer(int port) throws SocketException, IOException {
        this.port = port;
        this.socket = new DatagramSocket(port);
    }
    public DatagramPacket received() throws Exception
    {
        byte[] receiveData = new byte[1024];
        byte[] sendData;
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            socket.receive(receivePacket);
            return receivePacket;
    }
}
