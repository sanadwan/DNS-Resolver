package il.ac.idc.cs.sinkhole;

import java.io.IOException;


/**
 * According to the domain name query ip, only check ipv4
 * A domain name may resolve to multiple ips
 */
public class dnsR {
    private static int QCLASS;
    private static int QTYPE;
    private static Integer TTL;
    private static int RDLENGTH;
    private static int QDCOUNT;
    private static int ANCOUNT;
    private static int NSCOUNT;
    private static int ARCOUNT;
    private static StringBuilder domainParts = new StringBuilder();
    private static String QR;
    private static String OPCODE;
    private static String AA;
    private static String TC;
    private static String RD;
    private static String RA;
    private static String Z;
    private static String RCODE;
    // the original socket
    public UDPServer serverSocket;

    public dnsR() {
        try {
            // open a new socket on  port 5300
            serverSocket = new UDPServer(5300);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public dnsR(int port) {
        try {
            serverSocket = new UDPServer(port);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String byteToHex(byte b) {
        String res = "";
        int a = Integer.valueOf(b & 0xFF);
        res = Integer.toHexString(a);
        res = res.toUpperCase();

        if (res.length() == 1) {
            res = "0" + res;
        }

        return res;
    }

    public static String byteToHex(byte[] arr, int offset, int len) {
        String hexStr = "";

        for (int i = 0; i < len; i++) {
            hexStr += byteToHex(arr[i + offset]);
        }

        return hexStr;
    }
 
         // len bytes from the index starting from the highest bit
    public static String byteToBits(byte b, int index, int len) {
        String str = "";

        for (int i = 0; i < len; i++) {
            if (((b >> (7 - index - i)) & 0x01) == 0x01) {
                str += "1";
            } else {
                str += "0";
            }
        }

        return str;
    }

    private static int byteToInt(byte b) {
        return (b < 0) ? (b + 256) : b;
    }

    //dns message format: https://jocent.me/2017/06/18/dns-protocol-principle.html
    public static void getHeader(byte[] data, int len) {
        getFlags(data[2], data[3]);
        p("receive message parsing");
        p("ID is 0x" + byteToHex(data, 0, 2));
        p("QR=" + byteToBits(data[0], 0, 1));
        p("QPCODE=" + byteToBits(data[2], 1, 4));
        p("AA=" + byteToBits(data[2], 5, 1));
        p("TC=" + byteToBits(data[2], 6, 1));
        p("RD=" + byteToBits(data[2], 7, 1));
        p("RA=" + byteToBits(data[3], 0, 1));
        p("Z=" + byteToBits(data[3], 1, 3));
        p("RCODE=" + byteToBits(data[3], 4, 4));

        QDCOUNT = (data[4] << 8) | data[5];
        System.out.println("QDCOUNT " + QDCOUNT);
        ANCOUNT = (data[6] << 8) | data[7];
        System.out.println("ANCOUNT " + ANCOUNT);
        NSCOUNT = (data[8] << 8) | data[9];
        System.out.println("NSCOUNT" + NSCOUNT);
        ARCOUNT = (data[10] << 8) | data[11];
        System.out.println("ARCOUNT " + ARCOUNT);
    }
    static void getFlags(byte b1, byte b2) {
        // flags array
        QR = byteToBits(b1, 0, 1);
        OPCODE = byteToBits(b1, 1, 5);
        AA = byteToBits(b1,5,1);
        TC = byteToBits(b1,6,1);
        RD = byteToBits(b1,7,1);
        RA = byteToBits(b2,0,1);
        Z = byteToBits(b2,1,3);
        RCODE = byteToBits(b2,4,4);

    }

    public static String getQR() {
        return QR;
    }

    public static String getRCODE() {
        return RCODE;
    }

    public static int getANCOUNT() {
        return ANCOUNT;
    }
    public static String getServer(){
        return domainParts.toString();
    }
    public static int getARCOUNT() {
        return ARCOUNT;
    }
    public static long getTTL() {
        return TTL;
    }
    public static int getNSCOUNT() {
        return NSCOUNT;
    }

    public static void p(String s) {
        System.out.println(s);
    }

    // get random server from the list
    public static String randomRootServer() {
    String[] rootServer = new String[13];
    rootServer[0] = "198.41.0.4";
    rootServer[1] = "199.9.14.201";
    rootServer[2] = "192.33.4.12";
    rootServer[3] = "199.7.91.13";
    rootServer[4] = "192.203.230.10";
    rootServer[5] = "192.5.5.241";
    rootServer[6] = "192.112.36.4";
    rootServer[7] = "198.97.190.53";
    rootServer[8] = "192.36.148.17";
    rootServer[9] = "192.58.128.30";
    rootServer[10] = "193.0.14.129";
    rootServer[11] = "199.7.83.42";
    rootServer[12] = "202.12.27.33";

    int rndNum = (int)(Math.random() * (rootServer.length - 1));
    System.out.println(rndNum);
    return rootServer[rndNum];



    }

    // get the domain for the query and the authority
    static int getName(byte[] bArray, int index)
    {

        StringBuilder b = new StringBuilder();
        boolean state = false;
        int expectedLength = 0;
        int x = 0;
        boolean pointer = false;
        int i = 0;
        for (i = index; i < bArray.length - index; i++) {
            if(byteToBits(bArray[i], 0, 2).equals("11")){
                pointer = true;
                break;
            }
            if (state) {
                if(bArray[i] != 0) {
                    domainParts.append((char) bArray[i]);
                    x++;
                }
                if(x == expectedLength){
                 //   domainParts.append(b.toString());
                  //  b = new StringBuilder();
                    state = false;
                    x = 0;
                }

            }
            else{
                state = true;
                expectedLength = bArray[i];
                if(expectedLength == 0){
                    break;
                }
                if(domainParts.length() > 0) {
                    domainParts.append(".");
                }

             // System.out.println(expectedLength);
            }
        }
        if(pointer){
            int offset = byteToInt((byte)(bArray[i]<<2));
//            System.out.println("B " + byteToInt(bArray[y]));
//            System.out.println();
            offset = (offset<<8 | bArray[i+1]);
            System.out.println("index " + offset);
            //byte[] CArray = Arrays.copyOfRange(bArray, (offset - 12) + 1, bArray.length);
            getName(bArray, offset);
            i += 2;
        }
        return i;
    }

    public static void clearDomain(){        domainParts = new StringBuilder(); }

    public static int getAuth(byte[] bArray, int index) {
        //get the QTYPE
        QTYPE =  (bArray[index]<<8 | bArray[index+1]);
        //get the class
        QCLASS =  (bArray[index+2]<<8 | bArray[index+3]);
        if(QTYPE> 1){
            int tmp1 = (bArray[index+4]<<8 | bArray[index+5]);
            int tmp2 =  (bArray[index+6]<<8 | bArray[index+7]);
            TTL = (tmp1 << 16| tmp2);
            RDLENGTH = (short)(bArray[index+8]<<8 | bArray[index+9]);

            index= index+6;

        }


        return index + 4;
    }


}