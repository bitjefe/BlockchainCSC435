/*

1. Jeff Wiand / 2-27-19
2. Java 1.8
3. Compilation Instructions:
    >

4. Run Instructions  (REVIEW THESE PROCESS COORDINATION SCRIPTS)

   AllStart.Bat

   REM for three procesess:
   start java Blockchain 0
   start java Blockchain 1
   java Blockchain 2

   List of files needed for running the program
    - Blockchain.java
    - BlockchainLedgerSample.xml
    - BlockchainLog.txt
    - BlockInput0.txt
    - BlockInput1.txt
    - BlockInput2.txt

5. My Notes
    -

*/

//import sun.security.rsa.RSAPublicKeyImpl;


import javax.xml.bind.*;
import javax.xml.bind.annotation.*;
import javax.xml.transform.stream.StreamSource;
import java.math.BigInteger;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.security.*;

/*import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;*/

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

/* class ProcessBlock{
  int processID;
  PublicKey pubKey;
  int port;
  String IPAddress;
  } */


class Ports{
    public static int KeyServerPortBase = 4710;
    public static int UnverifiedBlockServerPortBase = 4820;
    public static int BlockchainServerPortBase = 4930;

    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int BlockchainServerPort;

    public void setPorts(int PID){
        KeyServerPort = KeyServerPortBase + (PID);
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (PID);
        BlockchainServerPort = BlockchainServerPortBase + (PID);
    }
}

class PublicKeyWorker extends Thread {
    Socket sock;
    PublicKey publicKey;
    static PublicKey[] pubKeyArray = new PublicKey[3];

    PublicKeyWorker (Socket s) {sock = s;}
    public void run(){
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String pubKey = in.readLine();
            String modulus = in.readLine();
            String publicExponent = in.readLine();
            String PIDString = in.readLine();

            publicKey = CreateRSAPublicKey(modulus,publicExponent);
            System.out.println("New RSAPublicKey = " + publicKey);

            int PID = Integer.parseInt(PIDString);
            System.out.println(PID);
            pubKeyArray[PID] = publicKey;

            sock.close();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException x){x.printStackTrace();}
    }

    public PublicKey CreateRSAPublicKey(String modulus, String publicExponent) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey myPublicKey;

        byte[] modulusBytes = modulus.getBytes();
        byte[] publicExponentBytes = publicExponent.getBytes();
        BigInteger modulusBigInt = new BigInteger(modulusBytes);
        BigInteger publicExponentBigInt = new BigInteger(publicExponentBytes);

        RSAPublicKeySpec rsaPublicKeySpec= new RSAPublicKeySpec(modulusBigInt, publicExponentBigInt);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        myPublicKey = keyFactory.generatePublic(rsaPublicKeySpec);
        return myPublicKey;
    }
}

class PublicKeyServer implements Runnable {
    //public ProcessBlock[] PBlock = new ProcessBlock[3]; // One block to store info for each process.

    public void run(){
        int q_len = 6;
        Socket sock;
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new PublicKeyWorker (sock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

class UnverifiedBlockServer implements Runnable {
    BlockingQueue<String> queue;
    int PID;
    UnverifiedBlockServer(BlockingQueue<String> queue, int PID){
        this.queue = queue;
        this.PID = PID;
    }

    class UnverifiedBlockWorker extends Thread {
        Socket sock;


        UnverifiedBlockWorker (Socket s) {sock = s;}
        public void run(){
            try{

                StringBuffer in = new StringBuffer();                                               // initialize a buffer for incoming stringwriter
                Reader reader = new InputStreamReader(sock.getInputStream());                       // initialize a reader object and connect it to the socket for unverified blocks

                int xmlInt;                                                                         // read in our marshalledXML block and append it to a temporary XMLStringSent of type String
                while ((xmlInt = reader.read()) != -1) in.append((char) xmlInt);                   // change this code up

                String XMLStringSent = in.toString();

                System.out.println("XML String sent = "  + XMLStringSent);
                queue.put(XMLStringSent);                                                           // add the XMLStringSent to the queue for consumption by the blockchain work server

                sock.close();                                                                       // close our current connection
            } catch (Exception x){x.printStackTrace();}                                             // catch any exceptions and print the stack to the user
        }
    }

    public void run(){
        int q_len = 6;
        Socket sock;
        System.out.println("Starting the Unverified Block Server input thread using " +
                Integer.toString(Ports.UnverifiedBlockServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
                sock = servsock.accept(); // Got a new unverified block
                new UnverifiedBlockWorker(sock).start(); // So start a thread to process it.
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

/* We have received unverified blocks into a thread-safe concurrent access queue. Just for the example, we retrieve them
in order according to their blockID. Normally we would retreive the block with the lowest time stamp first, or? This
is just an example of how to implement such a queue. It must be concurrent safe because two or more threads modifiy it
"at once," (mutiple worker threads to add to the queue, and consumer thread to remove from it).*/

class UnverifiedBlockConsumer implements Runnable {
    BlockingQueue<String> queue;
    int PID;
    UnverifiedBlockConsumer(BlockingQueue<String> queue, int PID){
        this.queue = queue; // Constructor binds our prioirty queue to the local variable.
        this.PID = PID;
    }

    public void run(){
        String data;
        PrintStream toServer;
        Socket sock;
        String newblockchain;
        String fakeVerifiedBlock;

        System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");


        try{
            while(true){ // Consume from the incoming queue. Do the work to verify. Mulitcast new blockchain
                data = queue.take(); // Will blocked-wait on empty queue
                System.out.println("Consumer got unverified: " + data);

                try{

                    StringBuffer in = new StringBuffer();
                    Reader reader = new StringReader(data);

                    int xmlInt=0;

                    while ((xmlInt = reader.read()) != -1) in.append((char) xmlInt);

                    String XMLStringSent = in.toString();


                    JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
                    Unmarshaller jaxbUnMarshaller = jaxbContext.createUnmarshaller();

                    StreamSource streamSource = new StreamSource(new StringReader(XMLStringSent));

                    JAXBElement<BlockRecord> blockRecordJAXBElement = jaxbUnMarshaller.unmarshal(streamSource,BlockRecord.class);

                    BlockRecord blockRecord = (BlockRecord) blockRecordJAXBElement.getValue();

                    System.out.println("Blockrecord receieved = " + blockRecord.getFLname());

                    data = blockRecord.getFLname();

                }catch (JAXBException e){
                    e.printStackTrace();
                }



                // Ordinarily we would do real work here, based on the incoming data.
                int j; // Here we fake doing some work (That is, here we could cheat, so not ACTUAL work...)
                for(int i=0; i< 100; i++){ // put a limit on the fake work for this example
                    j = ThreadLocalRandom.current().nextInt(0,10);
                    try{Thread.sleep(500);}catch(Exception e){e.printStackTrace();}
                    if (j < 3) break; // <- how hard our fake work is; about 1.5 seconds.
                }


                System.out.println("data = " + data);
                System.out.println("Blockchain.blockchain.indexOf(data) = "+ Blockchain.blockchain.indexOf(data));

	/* With duplicate blocks that have been verified by different procs ordinarily we would keep only the one with
           the lowest verification timestamp. For the example we use a crude filter, which also may let some dups through */

                if(Blockchain.blockchain.indexOf(data) < 0){ // Crude, but excludes most duplicates. FIX THIS ONLY ADDS 10 / 12 records correctly

                    fakeVerifiedBlock = "[" + data + " verified by P" + PID + " at time "
                            + Integer.toString(ThreadLocalRandom.current().nextInt(100,1000)) + "]\n";
                    System.out.println(fakeVerifiedBlock);
                    String tempblockchain = fakeVerifiedBlock + Blockchain.blockchain; // add the verified block to the chain

                    for(int i=0; i < Blockchain.numProcesses; i++){ // send to each process in group, including us:
                        sock = new Socket(Blockchain.serverName, (Ports.BlockchainServerPortBase + i));
                        toServer = new PrintStream(sock.getOutputStream());
                        toServer.println(tempblockchain); toServer.flush(); // make the multicast
                        sock.close();
                    }
                }
                Thread.sleep(1500); // For the example, wait for our blockchain to be updated before processing a new block
            }
        }catch (Exception e) {System.out.println(e);}
    }
}

// Incoming proposed replacement blockchains. Compare to existing. Replace if winner:

class BlockchainWorker extends Thread { // Class definition
    Socket sock; // Class member, socket, local to Worker.
    BlockchainWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
    public void run(){
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String data = "";
            String data2;
            while((data2 = in.readLine()) != null){
                data = data + data2;
            }
            Blockchain.blockchain = data; // Would normally have to check first for winner before replacing.
            System.out.println("         --NEW BLOCKCHAIN--\n" + Blockchain.blockchain + "\n\n");
            sock.close();
        } catch (IOException x){x.printStackTrace();}
    }
}

class BlockchainServer implements Runnable {
    public void run(){
        int q_len = 6; /* Number of requests for OpSys to queue */
        Socket sock;
        System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new BlockchainWorker (sock).start();
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}


@XmlRootElement
class BlockRecord{

    /* Examples of block fields: */

    String SHA256String;
    String SignedSHA256;
    String BlockID;
    String VerificationProcessID;
    String CreatingProcess;
    String PreviousHash;
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String Diag;
    String Treat;
    String Rx;


/* Examples of accessors for the BlockRecord fields. Note that the XML tools sort the fields alphabetically
     by name of accessors, so A=header, F=Indentification, G=Medical: */


    public String getASHA256String() {return SHA256String;}
     @XmlElement
    public void setASHA256String(String SH){this.SHA256String = SH;}

    public String getASignedSHA256() {return SignedSHA256;}
     @XmlElement
    public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}

    public String getACreatingProcess() {return CreatingProcess;}
     @XmlElement
    public void setACreatingProcess(String CP){this.CreatingProcess = CP;}

    public String getAVerificationProcessID() {return VerificationProcessID;}
      @XmlElement
    public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}

    public String getABlockID() {return BlockID;}
     @XmlElement
    public void setABlockID(String BID){this.BlockID = BID;}

    public String getFSSNum() {return SSNum;}
      @XmlElement
    public void setFSSNum(String SS){this.SSNum = SS;}

    public String getFFname() {return Fname;}
      @XmlElement
    public void setFFname(String FN){this.Fname = FN;}

    public String getFLname() {return Lname;}
      @XmlElement
    public void setFLname(String LN){this.Lname = LN;}

    public String getFDOB() {return DOB;}
     @XmlElement
    public void setFDOB(String DOB){this.DOB = DOB;}

    public String getGDiag() {return Diag;}
      @XmlElement
    public void setGDiag(String D){this.Diag = D;}

    public String getGTreat() {return Treat;}
     @XmlElement
    public void setGTreat(String D){this.Treat = D;}

    public String getGRx() {return Rx;}
     @XmlElement
    public void setGRx(String D){this.Rx = D;}

}

// Class Blockchain
public class Blockchain {

    static int PID;
    static String serverName = "localhost";
    static String blockchain = "[First block]";
    static int numProcesses = 3; // Set this to match your batch execution file that starts N processes with args 0,1,2,...N

    public Blockchain(int PID) {
        this.PID = PID;
    }
    //static int PID = 1; // Our process ID

    public static KeyPair generateKeyPair(long seed) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);

        return (keyGenerator.generateKeyPair());
    }



    public static String Marshaller(BlockRecord[] blockArrayNew, int index) throws JAXBException, InterruptedException {
        String realBlock = null;
        int incrementer = index;
        String stringXML;
        File xmlFile = new File("file.xml");
        Thread.sleep(1000);

        JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        StringWriter sw = new StringWriter();

        // CDE Make the output pretty printed:
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        //System.out.println(index + " records read.");
        System.out.println("Names from input:");

        System.out.println("  " + blockArrayNew[index].getFFname() + " " + blockArrayNew[index].getFLname());

        System.out.println("\n");


        jaxbMarshaller.marshal(blockArrayNew[index], sw);

        MultiSendNewBlock(sw);

        stringXML = sw.toString();

        return stringXML;
    }



    public BlockRecord[] BlockInput() {
        String FILENAME;
        String BlockReturned =null;

        BlockRecord[] blockArray = new BlockRecord[20];

        // Token indexes for input:
        final int iFNAME = 0;
        final int iLNAME = 1;
        final int iDOB = 2;
        final int iSSNUM = 3;
        final int iDIAG = 4;
        final int iTREAT = 5;
        final int iRX = 6;

        int pnum;
        int UnverifiedBlockPort;
        int BlockChainPort;

        if(PID == 0)         pnum = 0;
        else if (PID == 1)   pnum = 1;
        else if (PID == 2)   pnum = 2;
        else pnum = 0;


        System.out.println("Process number: " + pnum + " Ports: " + Ports.UnverifiedBlockServerPort + " " +
                Ports.BlockchainServerPort + "\n");

        switch(pnum){
            case 1: FILENAME = "BlockInput1.txt"; break;
            case 2: FILENAME = "BlockInput2.txt"; break;
            default: FILENAME= "BlockInput0.txt"; break;
        }

        System.out.println("Using input file: " + FILENAME);

        try {
            try (BufferedReader br = new BufferedReader(new FileReader(FILENAME))) {
                String[] tokens = new String[10];
                String stringXML;
                String InputLineStr;
                String suuid;
                UUID idA;

              /* JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
                Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
                StringWriter sw = new StringWriter();

                // CDE Make the output pretty printed:
                jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
*/
                int n = 0;

                while ((InputLineStr = br.readLine()) != null) {
                    blockArray[n] = new BlockRecord();

                    blockArray[n].setASHA256String("SHA string goes here...");
                    blockArray[n].setASignedSHA256("Signed SHA string goes here...");


                    idA = UUID.randomUUID();
                    suuid = new String(UUID.randomUUID().toString());
                    blockArray[n].setABlockID(suuid);
                    blockArray[n].setACreatingProcess("Process" + Integer.toString(pnum));
                    blockArray[n].setAVerificationProcessID("To be set later...");


                    tokens = InputLineStr.split(" +"); // Tokenize the input
                    blockArray[n].setFSSNum(tokens[iSSNUM]);
                    blockArray[n].setFFname(tokens[iFNAME]);
                    blockArray[n].setFLname(tokens[iLNAME]);
                    blockArray[n].setFDOB(tokens[iDOB]);
                    blockArray[n].setGDiag(tokens[iDIAG]);
                    blockArray[n].setGTreat(tokens[iTREAT]);
                    blockArray[n].setGRx(tokens[iRX]);

                    n++;
                }

            } catch (IOException e) {e.printStackTrace();}
        } catch (Exception e) {e.printStackTrace();}
        return blockArray;
    }


    public static void MultiSendNewBlock(StringWriter block) { // Multicast some data to each of the processes.
        Socket sock;
        PrintStream toServer;

        try{
            Thread.sleep(1000); // wait for keys to settle, normally would wait for an ack

            String fakeBlockA = "(Block#" + Integer.toString(((PID+2))) + " from P"+ PID + ")";

            for(int i=0; i< numProcesses; i++){// Send a sample unverified block A to each server
                sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(block);
                toServer.flush();
                sock.close();
            }
        }catch (Exception x) {x.printStackTrace ();}
    }


    public void MultiSendKeys(KeyPair keyPair) {
        Socket sock;
        PrintStream toServer;

        try{
            for(int i=0; i< numProcesses; i++){// Send our key to all servers.
                sock = new Socket(serverName, (Ports.KeyServerPortBase+i));
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println("Public Key" + keyPair.getPublic());                                 //print our public key modulus and public exponent in the keyServerPortBase
                toServer.println(PID);
                toServer.flush();
                sock.close();
            }
            Thread.sleep(1000); // wait for keys to settle, normally would wait for an ack
        }catch (Exception x) {x.printStackTrace ();}
    }

    public static void main(String args[]) throws Exception {
        int q_len = 8; /* Number of requests for OpSys to queue. Not interesting. */
        int PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); // Process ID

        //int PID = 0;

        System.out.println("BlockFramework control by Seth Weber-c to quit.\n");
        System.out.println("Using processID " + PID + "\n");

        final BlockingQueue<String> queue = new PriorityBlockingQueue<>();          // Concurrent queue for unverified blocks
        new Ports().setPorts(PID);                                                  // Establish OUR port number scheme, based on PID

        KeyPair keyPair = new Blockchain(PID).generateKeyPair(999+PID);

        new Thread(new PublicKeyServer()).start();                           // New thread to process incoming public keys
        new Thread(new UnverifiedBlockServer(queue,PID)).start();                   // New thread to process incoming unverified blocks
        new Thread(new BlockchainServer()).start();                                 // New thread to process incoming new blockchains
        try{Thread.sleep(1000);}catch(Exception e){}                          // Wait for servers to start.

        new Blockchain(PID).MultiSendKeys(keyPair);

        if(PublicKeyWorker.pubKeyArray[0].equals(PublicKeyWorker.pubKeyArray[1])){
            System.out.println("KEYS ARE EQUAL");
        }else{
            System.out.println("KEYS ARE NOT EQUAL");
            //System.out.println(PublicKeyWorker.pubKeyArray[0]);
            //System.out.println(PublicKeyWorker.pubKeyArray[1]);
            //System.out.println(PublicKeyWorker.pubKeyArray[2]);
        }

        /*
        //if PID = 2, trigger the multiSend of Keys
        if(PID ==2){
            new Blockchain(PID).MultiSendKeys(keyPair);
        }
        */

        BlockRecord[] blockRecord = new Blockchain(PID).BlockInput(); // Multicast some new unverified blocks out to all servers as data

        int indexCount = 0;
        while(blockRecord[indexCount]!=null){
            indexCount++;
        }

        System.out.println("indexCount = "+ indexCount);



        for(int i=0;i<indexCount;i++){

            System.out.println(blockRecord[i].getFLname());
            System.out.println("i = " + i);
            String XMLString = Marshaller(blockRecord,i);

        }



        try{Thread.sleep(1000);}catch(Exception e){} // Wait for multicast to fill incoming queue for our example.

        new Thread(new UnverifiedBlockConsumer(queue, PID)).start(); // Start consuming the queued-up unverified blocks

        
    }
}