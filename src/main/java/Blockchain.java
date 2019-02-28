/*

1. Jeff Wiand / 2-27-19
2. Java 1.8
3. Compilation Instructions:
    >

4. Run Instructions  (Run with blockScriptMaven.scpt)


    tell application "Terminal"
	    do script "cd /Users/jwiand/Desktop/JRW/depaul/CSC435/Blockchain/src/main/java && javac Blockchain.java && java Blockchain 0"
    end tell

    tell application "Terminal"
	    do script "cd /Users/jwiand/Desktop/JRW/depaul/CSC435/Blockchain/src/main/java && javac Blockchain.java && java Blockchain 1"
    end tell

    tell application "Terminal"
	    do script "cd /Users/jwiand/Desktop/JRW/depaul/CSC435/Blockchain/src/main/java && javac Blockchain.java && java Blockchain 2"
    end tell
    eof


   List of files needed for running the program
    - Blockchain.java
    - BlockchainLedgerSample.xml
    - BlockchainLog.txt
    - BlockInput0.txt
    - BlockInput1.txt
    - BlockInput2.txt

5. My Notes
    - This version of my program produces a BlockchainLedger.XML but it is only written by the last process (will only contain one process verificaiton in all the blocks).
    - The full ledger is produced and passed along (as you will be able to see in the BlockchainLog.txt. I will try to fix this with further submissions
    - Also note that i wrote the script to run Process 2 last and start the system although I dont know if this fits the criteria for "process 2 kicks off the system", so i put a maybe

*/



import javax.xml.bind.*;                                                //import the necessary XML bind libraries for marshalling / ummarshalling
import javax.xml.bind.annotation.*;
import javax.xml.transform.stream.StreamSource;                         //import StreamSource libraries for unmarshalling the XML back into a BlockRecord object
import java.math.BigInteger;                                            //import Big Integer library for RSA public key conversions
import java.security.interfaces.RSAPublicKey;                           //import RSAPublic Key libraries to regenerate public key after multicast
import java.security.spec.EncodedKeySpec;                               //import EncodedKeySpec libraries to help regenerate public key after multicast
import java.security.spec.InvalidKeySpecException;                      //import security.spec libraries for RSA Key creations
import java.security.spec.RSAPublicKeySpec;                             //import RSAPublicKeySpec libraries to help regenerate public key after multicast
import java.security.spec.X509EncodedKeySpec;                           //import X509EncodedKeySpec libraries to help regenerate public key after multicast
import java.util.*;                                                     //import the utilities library
import java.io.*;                                                       //import the input + output libraries
import java.net.*;                                                      //import the networking libraries
import java.util.concurrent.*;                                          //import the concurrent programming libraries for the BlockingQueue's
import java.security.*;                                                 //import the security library for KeyPair generations


import java.io.BufferedReader;                                          //import the BufferReader library to handle multi-threaded, multi-server communication
import java.io.FileReader;                                              //import the FileReader library to read in our BlockInput.txt files (0,1,2)
import java.io.IOException;                                             //import the IOException library to handle try/catch blocks for input / output

import static java.util.Base64.getDecoder;                              //import the Base64 encoder + decoder libraries to handle writing and reading data from BlockRecord object
import static java.util.Base64.getEncoder;

class ProcessBlock {
  int processID;                                                                            //local definition of processID of type int
  PublicKey pubKey;                                                                         //local definition of pubKey of type PublicKey
  int port;
  int credit;

  public void setProcessID(int processID) { this.processID = processID; }                   // setter and getter for processID of type ProcessID
  public int getProcessID() { return processID; }

  public void setPubKey(PublicKey pubKey) { this.pubKey = pubKey; }                         // setter and getter for pubKey of type PublicKey
  public PublicKey getPubKey() { return pubKey; }

  public void setPort(int port) { this.port = port; }                                       // setter and getter for port of type int
  public int getPort() {return port; }

  public void setCredit(int credit) { this.credit = credit; }                               // setter and getter for assigning credit for verification of Unverified block
  public int getCredit() { return credit;}
}

class Ports{                                                                                // class definition of Ports

    public static int KeyServerPortBase = 4710;                                             // set KeyServerPortBase to 4710, will add 0,1,2 to this depending on PID. in "setPorts(int PID)"
    public static int UnverifiedBlockServerPortBase = 4820;                                 // set UnverifiedBlockServerPortBase to 4820, will add 0,1,2 to this depending on PID. in "setPorts(int PID)"
    public static int BlockchainServerPortBase = 4930;                                      // set BlockchainServerPortBase to 4930, will add 0,1,2 to this depending on PID. in "setPorts(int PID)"
    public static int BlockLedgerServerPortBase = 5040 ;


    public static int KeyServerPort;                                                        // definition of KeyServerPort of type int
    public static int UnverifiedBlockServerPort;                                            // definition of UnverifiedBlockServerPort of type int
    public static int BlockchainServerPort;                                                 // definition of BlockchainServerPort of type int
    public static int BlockLedgerServerPort;                                               // definition of BlockcLedgerServerPort of type int


    public void setPorts(int PID){                                                          // method defintion of set ports. Takes in int PID (processID) with void return type.
        KeyServerPort = KeyServerPortBase + (PID);                                          // add PID to the KeyServerPortBase. Public Keys get multicast here
        UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (PID);                  // add PID to the UnverifiedBlockServerPortBase.  UnverifiedBlocks get multicast here
        BlockchainServerPort = BlockchainServerPortBase + (PID);                            // add PID to the BlockchainServerPortBase.  Blockchains get multicast here
        BlockLedgerServerPort = BlockLedgerServerPortBase + (PID);
    }
}

class PublicKeyWorker extends Thread {                                                                                  // worker thread class definition for PublicKeyServer
    Socket sock;                                                                                                        // local definition of sock of type Socket
    ProcessBlock[] PBlock;

    PublicKeyWorker(Socket s, ProcessBlock[] pBlock) {
        sock = s;                                                                                                        // set s to local definition of sock of type Socket }
        PBlock = pBlock;
    }

    public void run(){                                                                                                  // definition of run() for PublicKeyWorker. Will execute on every connect to the PublicKeyServer
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));                       // Buffered Reader object defintion to read in input for Socket sock
            int multiCastPID = Integer.parseInt(in.readLine());                                                         // read in the PID from multiCastKeys
            String modulusString = in.readLine();                                                                       // read in modulusString from multiCastKeys method
            String publicExponentString = in.readLine();                                                                // read in publicExponentString from multiCastKeys method

            BigInteger modulus = new BigInteger(modulusString);                                                         // convert modulusString to big integer:  see javaDocs https://docs.oracle.com/javase/6/docs/api/java/math/BigInteger.html#BigInteger%28java.lang.String%29
            BigInteger publicExponent = new BigInteger(publicExponentString);                                           // convert publicExponentString to big integer:  see javaDocs https://docs.oracle.com/javase/6/docs/api/java/math/BigInteger.html#BigInteger%28java.lang.String%29

            PBlock[multiCastPID] = new ProcessBlock();                                                                  // create new Process Block given the PID (0,1,2)
            PBlock[multiCastPID].setProcessID(multiCastPID);                                                            // set the Process ID to multiCastPID
            PBlock[multiCastPID].setCredit(0);                                                                          // set initial credit to zero for all processes (could do this in main but i interweaved all the PBlock's and Im running short on time. Refactor for future use!

            KeyFactory pubKeyFactory = KeyFactory.getInstance("RSA");                                                   // Get a new KeyFactory instance of type "RSA": referred to Java8 docs for KeyFactory https://docs.oracle.com/javase/8/docs/api/java/security/KeyFactory.html
            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus,publicExponent);                                 // generate new RSAPublic Key Spec : referred to java docs for RSAPublicKeySpec https://docs.oracle.com/javase/7/docs/api/java/security/spec/RSAPublicKeySpec.html#RSAPublicKeySpec(java.math.BigInteger,%20java.math.BigInteger)
            PublicKey pubKeyRegenerated = pubKeyFactory.generatePublic(pubKeySpec);                                     // Generate our new rebuilt public key using the KeyFactory method of .generatePublic(), feeding it the pubKeySpec defined directly above.   Referred to same java docs in KeyFactory

            PBlock[multiCastPID].setPubKey(pubKeyRegenerated);                                                          // set our public Key for this process
            PBlock[multiCastPID].setPort(Ports.KeyServerPort);                                                          // set our KeyServerPort for this process

            sock.close();                                                                                               // close our current connection only
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException x){x.printStackTrace();}                                                       // end of try /catch block, catches and handles Input/Output excepts and prints StackTrace to console if error
    }
}

class PublicKeyServer implements Runnable {
    ProcessBlock[] pBlock;
    public PublicKeyServer(ProcessBlock[] pBlock) {
        this.pBlock = pBlock;
    }                                                                             // server class definition for PublicKeyServer
    public void run(){                                                                                                  // run method for PublicKeyServer
        int q_len = 6;                                                                                                  // the amount of requests to hold in line before not accepting more requests, set to 6
        Socket sock;                                                                                                    // local definition of sock of type Socket
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));          // Print what port wer are starting to console
        try{                                                                                                            // enter try block
            ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);                                       // connect a servSock of type ServerSocket to KeyServerPort set in Ports class
            while (true) {                                                                                              // accept connections continuously
                sock = servsock.accept();
                new PublicKeyWorker(sock,pBlock).start();                                                                      // start PublicKeyWorker and feed it sock
            }
        }catch (IOException ioe) {System.out.println(ioe);}                                                             // catch IO exceptions and print the exception to console
    }
}

class UnverifiedBlockServer implements Runnable {                                                  // class defintion of UnverifiedBlockServer
    BlockingQueue<String> queue;                                                                   // local definition of BlockingQueue queue to hold strings
    int PID;                                                                                        // local definiton of process id PID of type int
    ProcessBlock[] PBlock;
    UnverifiedBlockServer(BlockingQueue<String> queue, int PID, ProcessBlock[] PBlock){                                    // constructor for UnverifiedBlockServer
        this.queue = queue;                                                                         // accepts a BlockingQueue and int and sets to local definitions above
        this.PID = PID;
        this.PBlock = PBlock;
    }

    class UnverifiedBlockWorker extends Thread {                                                    // inner class definition of UnverifiedBlockWorker
        Socket sock;                                                                                // inner class defintion of sock of type Socket
        ProcessBlock[] PBlock;

        UnverifiedBlockWorker(Socket s, ProcessBlock[] PBlock) {                                    // UnverifiedBlockWorker Constructor
            sock = s;
            PBlock = PBlock;
        }
        public void run(){                                                                          // run method definiton for UnverifiedBlockWorker
            try{
                StringBuffer inBuffer = new StringBuffer();                                             // initialize a buffer "inBuffer" of type StringBuffer
                InputStreamReader inputStreamReader = new InputStreamReader(sock.getInputStream());      // initialize a reader object and connect it to the socket for unverified blocks

                int xmlInt;                                                                         // inner class definition of xmlInt of type int
                                                                                                    // set the integer representation of our InputStreamReader (marshalledXML block) to xmlInt of type int
                while ((xmlInt = inputStreamReader.read()) != -1){                                  // while xmlInt is not equal -1, meaning as long as there is input to be read:
                    inBuffer.append((char) xmlInt);                                                 // append the read in integers (cast to char) to our inBuffer of type StringBuffer
                }

                String XMLStringSent = inBuffer.toString();                                          // convert our inBuffer to XMLStringSent of type String. This will be added to our queue of unverifiedBlocks

                System.out.println("XML String sent \n"  + XMLStringSent);                          // prove that our blocks are sent to the unverified blockserver as XML, print to console (you can view this in the BlockchainLog.txt look for XML String sent)
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
                new UnverifiedBlockWorker(sock,PBlock).start(); // So start a thread to process it.
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}


class UnverifiedBlockConsumer implements Runnable {                                             // class defintion of UnverifiedBlockConsumer
    BlockingQueue<String> queue;                                                                // local definition of BlockingQueue queue to hold strings
    int PID;                                                                                    // local definiton of process id PID of type int
    KeyPair keyPair;                                                                            // local definiton of keyPair of type KeyPair
    ProcessBlock[] PBlock;                                                                      // local definiton of PBlock of type ProcessBlock[]

    UnverifiedBlockConsumer(BlockingQueue<String> queue, int PID, KeyPair keyPair, ProcessBlock[] PBlock) {            // UnverifiedBlocKConsumer constructor
        this.queue = queue;                                                                              // takes in queue, PID, keyPair and PBlock and sets to local definitions of each
        this.PID = PID;
        this.keyPair = keyPair;
        this.PBlock = PBlock;
    }

    public void run() {                                                                         //local run() method for UnverifiedBlocKConsumer
        String data;                                                                            // local definition of data of type String
        PrintStream toServer;                                                                   // local definitions of toServer of type PrintStream
        Socket sock;                                                                            // local definition of sock of type Socket
        String newblockchain;                                                                   // local definition of newblockchain of type String
        String verifiedBlock;                                                                   // local definition of verifiedBlock of type String
        BlockRecord blockRecord = null;                                                         // local definition of blockRecord of type BlockRecord. set to null initially
        int blockNumber = 1;                                                                    // local definition of blockNumber of type int set to 1. First real block added to the blockchain after dummy block
        String SHAHashString;                                                                   // local definition of SHAHashString of type String

        ArrayList<BlockRecord> blockLedgerList = new ArrayList();                               // local definition of blockLedgerList of type Arraylist. It holds BlockRecords to be added to the blockchain

        System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");          // tell the console we are starting the Unverified Block Priority Queue

        try {
            while (true) {                                                                              // while their are blocks to consume, take a block from the queue
                data = queue.take();
                System.out.println("Consumer got unverified: " + data);                                 // print which unverified block the consumer received from the queue

                try {

                    StringBuffer inBuffer = new StringBuffer();                                             // initialize a buffer "inBuffer" of type StringBuffer
                    Reader reader = new StringReader(data);                                              // initialize a reader object and connect it to the socket for unverified blocks

                    // inner class definition of xmlInt of type int
                    int xmlInt;                                                                          // set the integer representation of our reader (marshalledXML block) to xmlInt of type int
                    while ((xmlInt = reader.read()) != -1){                                              // while xmlInt is not equal -1, meaning as long as there is input to be read:
                        inBuffer.append((char) xmlInt);                                                 // append the read in integers (cast to char) to our inBuffer of type StringBuffer
                    }

                    String XMLStringSent = inBuffer.toString();                                         // set our inBuffer to String XMLStringSent

                    JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);               //create a new JAXB instance of BlockRecord class
                    Unmarshaller jaxbUnMarshaller = jaxbContext.createUnmarshaller();                   // unmarshaller object to unmarshal XMLStringSent

                    StreamSource streamSource = new StreamSource(new StringReader(XMLStringSent));              //use StreamSource object to prepare XMLString to be unmarshalled into BlockRecord JAXBelement below: Used https://docs.oracle.com/javase/8/docs/api/javax/xml/transform/stream/StreamSource.html as reference

                    JAXBElement<BlockRecord> blockRecordJAXBElement = jaxbUnMarshaller.unmarshal(streamSource, BlockRecord.class);              // Create new JAXBElement of type BlockRecord. Unmarshal XML to BLockRecord class: Used java docs for this line and next line of code: https://docs.oracle.com/javase/8/docs/api/javax/xml/bind/JAXBElement.html

                    blockRecord = (BlockRecord) blockRecordJAXBElement.getValue();                                                              // cast the JAXB element to type BlockRecord so we can call setters/getters

                    data = blockRecord.getABlockID();                                                                   //use the UUID as a filter for data per instructions. Possibly change this for next submission

                    //put these verification steps into their own function! Call twice with different input strings == cleaner code (works for now though)

                    // Verification of ABlockID
                    //create our signed UUID
                    String blockSignedUUID = blockRecord.getASignedUUIDSHA256();

                    // used given workA.java from CE to produce these steps
                    // create MessageDigest object of instance "SHA-256" and get bytes from blockRecord SignedUUID
                    MessageDigest mdSignedUUID = MessageDigest.getInstance("SHA-256");
                    mdSignedUUID.update(blockSignedUUID.getBytes());

                    byte signedUUIDBytes[] = mdSignedUUID.digest();
                    StringBuffer sbSignedUUID = new StringBuffer();
                    for (int i = 0; i < signedUUIDBytes.length; i++) {
                        sbSignedUUID.append(Integer.toString((signedUUIDBytes[i] & 0xff) + 0x100, 16).substring(1));
                    }

                    //UUID Signed String
                    String blockSignedUUIDString = sbSignedUUID.toString();

                    byte[] SignatureUUIDBytes = signData(blockSignedUUIDString.getBytes(), keyPair.getPrivate());                       // get bytes of Signed UUID String
                    boolean verifiedSignedUUID = verifySig(blockSignedUUIDString.getBytes(), keyPair.getPublic(), SignatureUUIDBytes);   //verified if it corresponds to public key sig

                    System.out.println("UUID Verified = " + verifiedSignedUUID);                                                            // print to the console if the verification was true or false


                    // Verification of ASignedSHA256: repeat steps directly above for SHA256InputData
                    //create our signed SHA256
                    String signedSHA256InputData = blockRecord.getASignedSHA256();

                    MessageDigest mdSignedSHA256InputData = MessageDigest.getInstance("SHA-256");
                    mdSignedSHA256InputData.update(signedSHA256InputData.getBytes());

                    byte signedSHA256InputDataBytes[] = mdSignedSHA256InputData.digest();
                    StringBuffer sbSignSHA256InputData = new StringBuffer();
                    for (int i = 0; i < signedSHA256InputDataBytes.length; i++) {
                        sbSignSHA256InputData.append(Integer.toString((signedSHA256InputDataBytes[i] & 0xff) + 0x100, 16).substring(1));
                    }

                    //UUID Signed String
                    String signedSHA256InputDataString = sbSignSHA256InputData.toString();

                    byte[] signatureSHA256InputDataBytes = signData(signedSHA256InputDataString.getBytes(), keyPair.getPrivate());                                    // get bytes of Signed Input Data SHA String
                    boolean verifiedSignedSHA256InputData = verifySig(signedSHA256InputDataString.getBytes(), keyPair.getPublic(), signatureSHA256InputDataBytes);   //verified if it corresponds to public key sig

                    System.out.println("SHA Input Data Verified = " + verifiedSignedSHA256InputData);                                                                // print to the console if the verification was true or false
                } catch (JAXBException e) { e.printStackTrace(); }                                                                                      //catch any JAXBExceptions here


                //if the blockchain only contains [first-block]:  Had to hack this together since the first block isn't XML format simply a 13 char length string
                if (Blockchain.blockchain.length() == 13) {
                    blockRecord.setBlockNum(1);                             // set the BlockNumber as 1 here
                    SHAHashString = "FirstBlockHashString";                 // fake the firstblockHash by setting it equals to "FirstBlockHashString" here
                } else {
                    blockNumber++;                                          //increment BlockNum for every new block prepended to the blockchain
                    blockRecord.setBlockNum(blockNumber);                   //set the BlockNum to 1 plus the previous BlockNum (first real block added will be 2)
                    SHAHashString = blockRecord.getASHA256String();         // set the SHAHashString to the real SHAHash string if it's not the first dummy block.
                }

                String verificationProcessID = ("P" + PID);
                blockRecord.setAVerificationProcessID(verificationProcessID);     // set the verification signature with our PID

                String UB = SHAHashString + blockNumber + verificationProcessID;        // create String of previous block SHA hash, blockNumber, and verificationProcessID

                int blockchainLength = Blockchain.blockchain.length();                  // set our blockchain length before calling Work(). will feed this into Work() to periodically check if the blockchain length is changed

                Work(blockRecord, UB, blockchainLength);                            // do our real work here with Work()

                //System.out.println("data = " + data);
                //System.out.println("Blockchain.blockchain.indexOf(data) = " + Blockchain.blockchain.indexOf(data));

                if (Blockchain.blockchain.indexOf(data) < 0) {                              //  Excludes all duplicates based on block UUID

                    verifiedBlock = "[Block" + blockRecord.getBlockNum() + " verified by P" + PID /*blockRecord.getAVerificationProcessID()*/ + " at time "
                            + timeStamp(PID) + "]\n";
                    System.out.println(verifiedBlock);

                    //add block to ledger here??
                    //add the full block not just the verified block string?

                    blockLedgerList.add(blockRecord);
                    System.out.println("blocks in ledger = " +blockLedgerList.size());

                    String idStrings = MarshallertoLedger(blockLedgerList, PID, PBlock);

                    String tempblockchain = idStrings + Blockchain.blockchain;

                    for (int i = 0; i < Blockchain.numProcesses; i++) {                                                 // connect to the blockchain server ports and multicast the new blockchain ledger
                        sock = new Socket(Blockchain.serverName, (Ports.BlockchainServerPortBase + i));
                        toServer = new PrintStream(sock.getOutputStream());
                        toServer.println(tempblockchain);
                        toServer.flush();
                        sock.close();
                    }
                }
                Thread.sleep(1500);                                                                               // sleep for 1500 millis to allow all servers to receive the new blockchain safetly
            }
        } catch (Exception e) { System.out.println(e);}                                                                 // catch any exceptions here
    }

    private void Work(BlockRecord blockRecord, String UB, int blockchainLength) {                               // definition of function Work which will solve puzzle to compete for verification of block. Used WorkA.java given by CE here

        String randString;                                                                                      // local work definition of randString of type String

        String concatString = "";                                                                               // local work definition of concatString of type String: used to concatenate randString (seedGuess) to our UB string: UB =  String of previous block SHA hash, blockNumber, and verificationProcessID
        String stringOut = "";                                                                                  // local work defintiion of stringOut of type String: holds Hash of potential solution in puzzle solving loop

        String stringIn = UB;                                                                                   // String of previous block SHA hash, blockNumber, and verificationProcessID

        randString = randomAlphaNumeric(8);                                                              // set randString to a random AlphaNumeric of length 8
        System.out.println("Our random seed string: " + randString + "\n");                                     // print seed guess to console
        System.out.println("Concatenated: " + stringIn + randString + "\n");                                    // print UB + seed Guess to console


        int workNumber = 0;                                                                                     // set workNumber to 0 and set boundaries of:
        workNumber = Integer.parseInt("0000", 16);                                                    //lower hex boundary
        System.out.println("0x0000 = " + workNumber);

        workNumber = Integer.parseInt("FFFF", 16);                                                    // upper hex boundary
        System.out.println("0xFFFF = " + workNumber + "\n");

        try {

            for (int i = 1; i < 20; i++) {                                                                     // attempt work puzzle no more than 20 times
                randString = randomAlphaNumeric(8);                                                      // regenerate randString (guess Seed)
                concatString = stringIn + randString;                                                           // reset concatString with new guess seed
                MessageDigest MD = MessageDigest.getInstance("SHA-256");
                byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8"));
                stringOut = DatatypeConverter.printHexBinary(bytesHash);
                System.out.println("Hash is: " + stringOut);                                                     // get the bytes of the Hash and print Hex value
                workNumber = Integer.parseInt(stringOut.substring(0, 4), 16);                              // pull out the workNumber to since if first 16 bits are between our upper and lower hex boundaries
                System.out.println("First 16 bits " + stringOut.substring(0, 4) + ": " + workNumber + "\n");      // print the first 16 bits
                if (workNumber < 20000) {                                                                         // if worknumber is below 20000, we say the puzzle is solved and setAGuessSeed in the blockrecord
                    System.out.println("Puzzle solved!");
                    System.out.println("The seed was: " + randString);
                    blockRecord.setAGuessSeed(randString);


                    // SET CREDIT HERE?????????



                    break;
                }

                // if blockchain length is the same, do nothing
                if (blockchainLength == Blockchain.blockchain.length()) {
                    System.out.println("Blockchain is the same!!! ");               // in my runs the blockchain never changes in this loop. Not 100% sure this is working. will put maybe on checklist here

                } else {
                    int newBlockNum = blockRecord.getBlockNum()+1;                  // else, set newBlockNum to 1 plus old blockNum
                    blockRecord.setBlockNum(newBlockNum);
                    Work(blockRecord, UB, blockchainLength);                        // call Work again on our unverifiedBlock
                    System.out.println("Blockchain has changed");                   // print to console blockchain has changed
                    break;
                }

                Thread.sleep(2000);                                     // sleep 2000 millis to extend work session
            }
        } catch (Exception ex) { ex.printStackTrace(); }                       // catch any exceptions in Work here
    }

    public static String randomAlphaNumeric(int count) {                                        // function definition of randomAlphaNumeric for use in Work function: Used from examples given by CE in assignment workA.java
        final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";             // takes in an int and returns a randomAlphaNumeric String of that length of int
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int) (Math.random() * ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {               // function definiion of signData for use in unverifiedBlockConsumer:  Code base from workA.java given by CE
        Signature signer = Signature.getInstance("SHA1withRSA");                                // get Signature SHA1WithRSA instance
        signer.initSign(key);                                                                   // initiate the signature with the privateKey given
        signer.update(data);                                                                    // update the byte[] data given
        return (signer.sign());                                                                 // return the signed hash
    }

    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {  // function definiion of verifySig for use in unverifiedBlockConsumer:  Code base from workA.java given by CE
        Signature signer = Signature.getInstance("SHA1withRSA");                                // get Signature SHA1WithRSA instance
        signer.initVerify(key);                                                                 // initiate the signature verification with the publickey given
        signer.update(data);                                                                    // update the byte[] data given
        return (signer.verify(sig));                                                            // return the verification of hash boolean (true or false)
    }

    public static String timeStamp(int PID) {                                                       //custom TimeStamping function
        Date date = new Date();                                                                     // same code as below in BlockRecord. takes int and returns a timestamp to be added to blockrecord
        String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
        String timeStampVerified = T1 + "." + PID; // No timestamp collisions!
        return timeStampVerified;
    }

    public static String MarshallertoLedger(ArrayList<BlockRecord> blockRecordtoAdd, int PID, ProcessBlock[] PBlock) throws JAXBException, InterruptedException, IOException {         // function defintion of MarshallerToLedger: writes XML to BlockchainLedger.xml file
        Thread.sleep(1000);                                                                         // sleep at beginning of these function to settle simulatenous marshalling / writing

        int Credit0 = 0;                                                                            // reinitialize credit for each process at start of MarshallerToLedger call
        int Credit1 = 0;
        int Credit2 = 0;

        JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);                           // get new JAXBContext object of instance type BlockRecord.class
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();                                     // create our marshaller object
        StringWriter sw = new StringWriter();                                                           // create our StringWriter object

        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);                             // set the marshaller output to look formatted (easy to read)

        String BlockIDStrings ="";
        for (int i = 0; i < blockRecordtoAdd.size(); i++) {
            jaxbMarshaller.marshal(blockRecordtoAdd.get(i), sw);                                        // marshal the entire arrayList containing blockRecords in the ledger to Stringwriter as XML
            BlockIDStrings = "["+blockRecordtoAdd.get(i).getABlockID()+"]";                             // concatentate BlockIDStrings for visual of UUID's appended to blockchain

            if(blockRecordtoAdd.get(i).getAVerificationProcessID().equals("P0")) {                      //Credit loops based on ProcessVerificationID. adds 1 to appropriate process based on arrayList of verified blocks
                Credit0+=1;
                PBlock[0].setCredit(Credit0);                                                           // setCredit for the appropriate PID in PBlock
            }
            else if(blockRecordtoAdd.get(i).getAVerificationProcessID().equals("P1")){
                Credit1+=1;
                PBlock[1].setCredit(Credit1);
            }
            else if(blockRecordtoAdd.get(i).getAVerificationProcessID().equals("P2")){
                Credit2+=1;
                PBlock[2].setCredit(Credit2);
            }
        }

        String fullBlock = sw.toString();                                                               // writer or StringWriter to string type and set that equal to fullBlock of type String
        String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";             // define the XMLHeader to strip the fullBlocks of it
        String cleanBlock = fullBlock.replace(XMLHeader, "");                               // strip XMLHeaders from fullBlock

        String XMLBlockLedger = XMLHeader + "\n<BlockLedger>" + cleanBlock + "</BlockLedger>";          // set the XMLBlockLedger string with teh appropriate <BlockLedger> root element

        MultiCastLedger(XMLBlockLedger);                                                               // call MultiCastLedger to send the XML marshalled BlockLedger to the 4th server: BlockLedgerServer

        return BlockIDStrings;                                                                          // return the UUID string to be appened to blockchain and multicast to the BlockchainServer
    }

    private static void MultiCastLedger(String xmlBlockLedger) throws IOException {
        PrintStream toServer;                                                                           // local definitions of toServer of type PrintStream
        Socket sockToLedger;                                                                            // local definition of sock of type Socket

        for (int i = 0; i < Blockchain.numProcesses; i++) {                                                 // connect to the blockLedgerserver ports and multicast the new blockchain ledger
            sockToLedger = new Socket(Blockchain.serverName, (Ports.BlockLedgerServerPortBase + i));
            toServer = new PrintStream(sockToLedger.getOutputStream());
            toServer.println(xmlBlockLedger);
            toServer.flush();
            sockToLedger.close();
        }
    }
}

class BlockchainWorker extends Thread {                             // BlockchainWorker class definition
    Socket sock;                                                    // local definition of sock of type Socket

    BlockchainWorker (Socket s) {sock = s;}                           // BlockchainWorker Constructor
    public void run(){                                                // blockchainWorker run method
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));           // read in the new blockchain and multi-cast to other processes
            String data = "";
            String data2;

            while((data2 = in.readLine()) != null){
                data = data + data2;
            }

            Blockchain.blockchain = data;      // add in another queue to queue competing blockchains for further submissions
            System.out.println("         --NEW BLOCKCHAIN--\n" + Blockchain.blockchain + "\n\n");

            sock.close();                                       //close current connection
        } catch (IOException x){x.printStackTrace();}           // catch IO exceptions and print stacktrace if found
    }
}

class BlockchainServer implements Runnable {                        // class definition of Blockchain Server
    public void run(){
        int q_len = 6;                                              // number of queued requests set to 6.
        Socket sock;                                                // local sock defintion of type Socket
        System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
        try{
            ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);            // print to the console the server we are connecting to and port
            while (true) {
                sock = servsock.accept();
                new BlockchainWorker (sock).start();                                    //connects at BlockchainServerPort and launches a BlockchainWorker
            }
        }catch (IOException ioe) {System.out.println(ioe);}                             // catch IO exceptions and print stackTrace if found
    }
}


class BlockLedgerWorker extends Thread {
    Socket sock;

    BlockLedgerWorker (Socket s) {sock = s;}
    public void run(){
        try{
            BlockLedger blockLedger = null;

            StringBuffer inBuffer = new StringBuffer();                                             // initialize a buffer "inBuffer" of type StringBuffer
            InputStreamReader inputStreamReader = new InputStreamReader(sock.getInputStream());      // initialize a reader object and connect it to the socket for unverified blocks

            int xmlInt;                                                                         // inner class definition of xmlInt of type int
            // set the integer representation of our InputStreamReader (marshalledXML block) to xmlInt of type int
            while ((xmlInt = inputStreamReader.read()) != -1){                                  // while xmlInt is not equal -1, meaning as long as there is input to be read:
                inBuffer.append((char) xmlInt);                                                 // append the read in integers (cast to char) to our inBuffer of type StringBuffer
            }

            String XMLStringSent = inBuffer.toString();                                          // convert our inBuffer to XMLStringSent of type String. This will be added to our queue of unverifiedBlocks

            System.out.println("New Ledger \n"  + XMLStringSent);                          // prove that our blocks are sent to the unverified blockserver as XML, print to console (you can view this in the BlockchainLog.txt look for XML String sent)

            JAXBContext jaxbContext = JAXBContext.newInstance(BlockLedger.class);               //create a new JAXB instance of BlockRecord class
            Unmarshaller jaxbUnMarshaller = jaxbContext.createUnmarshaller();                   // unmarshaller object to unmarshal XMLStringSent

            StreamSource streamSource = new StreamSource(new StringReader(XMLStringSent));              //use StreamSource object to prepare XMLString to be unmarshalled into BlockRecord JAXBelement below: Used https://docs.oracle.com/javase/8/docs/api/javax/xml/transform/stream/StreamSource.html as reference

            JAXBElement<BlockLedger> blockLedgerJAXBElement = jaxbUnMarshaller.unmarshal(streamSource, BlockLedger.class);              // Create new JAXBElement of type BlockRecord. Unmarshal XML to BLockRecord class: Used java docs for this line and next line of code: https://docs.oracle.com/javase/8/docs/api/javax/xml/bind/JAXBElement.html


            blockLedger = blockLedgerJAXBElement.getValue();
            System.out.println(blockLedger.getBlockRecord());

            File BlockchainLedger = new File("BlockchainLedger.xml");                               // create new File = "BlockchainLedger.xml" that contains the ledger as XML
            //this only write PO's verified blocks... maybe create new BlockLedger process block and write it back to main like PBlock
            //if (PID == 0) {
            FileOutputStream outputToBLockchainLedgerXML = new FileOutputStream(BlockchainLedger);          //open up a new FileOutputStream object to BlockchainLedger.XML
            byte[] BlockchainLedgerBytes = XMLStringSent.getBytes();                                       //get the bytes of the String XMLBlockledger set above
            outputToBLockchainLedgerXML.write(BlockchainLedgerBytes);                                       //write the BlockchainLedgerBytes to the file = "BlockchainLedger.XML"
            outputToBLockchainLedgerXML.close();                                                            //close the FileOutputStream

            sock.close();                                                                                   // close current connection only
        } catch (IOException | JAXBException x){x.printStackTrace();}
    }
}

class BlockLedgerServer implements Runnable {                               //added a 4th server to handle just the XML BlockLedger
    public void run(){
        int q_len = 6;                                                      // number of queued requests set to 6.
        Socket sock;                                                        // local sock defintion of type Socket
        System.out.println("Starting the BlockLedger server input thread using " + Integer.toString(Ports.BlockLedgerServerPort));      // print to the console the server we are connecting to and port
        try{
            ServerSocket servsock = new ServerSocket(Ports.BlockLedgerServerPort, q_len);
            while (true) {
                sock = servsock.accept();
                new BlockLedgerWorker (sock).start();                                   //connects at BlockLedgerServerPort and launches a BlockLedgerWorker
            }
        }catch (IOException ioe) {System.out.println(ioe);}                             // catch IO exceptions and print stackTrace if found
    }
}

@XmlRootElement
class BlockLedger{                                                              //custom BlockLedger class to hold BlockRecord elements
    BlockRecord blockRecord;

    public BlockRecord getBlockRecord(){return blockRecord;}                    // getter and setter for BlockRecord elements
    @XmlElement
    public void setBlockRecord(BlockRecord BR) {this.blockRecord = BR;}

}


@XmlRootElement
class BlockRecord{

    //BlockRecord local field definitions
    Integer BlockNum;
    String timeStamp;
    String signedUUIDSHA256;
    String SHA256String;
    String SignedSHA256;
    String BlockID;
    String VerificationProcessID;
    String guessSeed;
    String CreatingProcess;
    String PreviousHash;
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String Diag;
    String Treat;
    String Rx;

    //Setters and Getters for BlockRecord class
    public Integer getBlockNum() {return BlockNum;}
    @XmlElement
    public void setBlockNum(Integer BNUM){this.BlockNum = BNUM;}                                         //Block number added to verified block

    public String getABlockID() {return BlockID;}
    @XmlElement
    public void setABlockID(String BID){this.BlockID = BID;}                                            // UUID

    public String getACreatingProcess() {return CreatingProcess;}
    @XmlElement
    public void setACreatingProcess(String CP){this.CreatingProcess = CP;}                              //Process + PID

    public String getASignedUUIDSHA256() {return signedUUIDSHA256;}
    @XmlElement
    public void setASignedUUIDSHA256(String SUUID){this.signedUUIDSHA256 = SUUID;}                      // UUID signed by Private Key


    public String getTimeStamp() {return timeStamp;}
    @XmlElement
    public void setTimeStamp(String TIME){this.timeStamp = TIME;}                                       // Block TimeStamp



    public String getASHA256String() {return SHA256String;}
     @XmlElement
    public void setASHA256String(String SH){this.SHA256String = SH;}                                    // SHA String of InputData

    public String getASignedSHA256() {return SignedSHA256;}
     @XmlElement
    public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}                                    // Signed SHA String of InputData by Private Key


    public String getAVerificationProcessID() {return VerificationProcessID;}
      @XmlElement
    public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}                //Verifing Process ID put into unverified block

    public String getAGuessSeed(){return guessSeed;}
    @XmlElement
    public void setAGuessSeed(String GS) {this.guessSeed = GS;}                                         // randString in Work method

    public String getFSSNum() {return SSNum;}
      @XmlElement
    public void setFSSNum(String SS){this.SSNum = SS;}                                                  // social security #

    public String getFFname() {return Fname;}
      @XmlElement
    public void setFFname(String FN){this.Fname = FN;}                                                  // first name

    public String getFLname() {return Lname;}
      @XmlElement
    public void setFLname(String LN){this.Lname = LN;}                                                  // last name

    public String getFDOB() {return DOB;}
     @XmlElement
    public void setFDOB(String DOB){this.DOB = DOB;}                                                    // date of birth

    public String getGDiag() {return Diag;}
      @XmlElement
    public void setGDiag(String D){this.Diag = D;}                                                      // diagnosis

    public String getGTreat() {return Treat;}
     @XmlElement
    public void setGTreat(String D){this.Treat = D;}                                                    // treatment

    public String getGRx() {return Rx;}
     @XmlElement
    public void setGRx(String D){this.Rx = D;}                                                          // prescription


}

public class Blockchain {

    static int PID;                                                         // local definiton of process id PID of type int
    static String serverName = "localhost";                                 // set our servername to localhost. Extend to IP addresses in further submissions
    static String blockchain = "[First block]";                             // insert a dummy block of text only "First Block" to the start of the blockchain
    static int numProcesses = 3;                                            // set numprocesses equal to 3. will only work with 3 processes
    //static int numProcesses = 1;                                          // make this dynamically read # of processes for future submissions

    public Blockchain(int PID) {                                        // constructor for Blockchain that takes in PID only
        this.PID = PID;
    }

    public static KeyPair generateKeyPair(long seed) throws Exception {                         //keyGenerate method. Takes in a seed of type long and returns a Keypair
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");                    //get instance of RSA for keyGenerator object
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");        // insure the key is random and set it
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);                                             // give the keyGeneator the algorithm = 1024, rng

        return (keyGenerator.generateKeyPair());                                                // return the Key pair
    }

    public static String Marshaller(BlockRecord[] blockArrayNew, int index) throws JAXBException, InterruptedException {        // custom Marshaller function. returns a String of XML and kicks of the MultiSending of Blocks
        String realBlock = null;                                                                                                //local definitions of Strings and Files
        int incrementer = index;
        String stringXML;
        File xmlFile = new File("file.xml");
        Thread.sleep(1000);                                                                                             // sleep for 1000 millis to let the program initialization settle

        // create our necessary objects for marshalling a BlockRecord class
        JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
        StringWriter sw = new StringWriter();

        //use the .setProperty method to format the output neatly
        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        // print the first and last names of the input data
        System.out.println("Names from input:");
        System.out.println("  " + blockArrayNew[index].getFFname() + " " + blockArrayNew[index].getFLname());
        System.out.println("\n");

        // marshal the BlockRecord to stringwriter object sw
        jaxbMarshaller.marshal(blockArrayNew[index], sw);

        //Multi-cast the blocks to all processes
        MultiSendNewBlock(sw);

        //create a string of XML from stringwriter object sw and return int
        stringXML = sw.toString();

        return stringXML;


    }


    public BlockRecord[] BlockInput(KeyPair keyPair) {                  // BlockInput method definition. Used blockchain utilities program from CE to build these
        String FILENAME;                                                // define the FILENAME to read in
        String BlockReturned =null;

        BlockRecord[] blockArray = new BlockRecord[20];                 // initialize a BlockRecord of size 20

        // set the input field indexes
        final int iFNAME = 0;
        final int iLNAME = 1;
        final int iDOB = 2;
        final int iSSNUM = 3;
        final int iDIAG = 4;
        final int iTREAT = 5;
        final int iRX = 6;

        // set PID to pnum of type int.
        int pnum;

        // determine which process we are in
        if(PID == 0)         pnum = 0;
        else if (PID == 1)   pnum = 1;
        else if (PID == 2)   pnum = 2;
        else pnum = 0;


        // print the process currently in and what ports are spun up
        System.out.println("Process number: " + pnum + " Ports: " + Ports.KeyServerPort + Ports.UnverifiedBlockServerPort + " " +
                Ports.BlockchainServerPort + Ports.BlockLedgerServerPort + "\n");

        // read in the correct .txt file based on the PID (pnum)
        switch(pnum){
            case 1: FILENAME = "BlockInput1.txt"; break;
            case 2: FILENAME = "BlockInput2.txt"; break;
            default: FILENAME= "BlockInput0.txt"; break;
        }

        System.out.println("Using input file: " + FILENAME);

        //create our timestamp
        Date date = new Date();
        String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
        String TimeStampString = T1 + "." + pnum;
        System.out.println("Timestamp: " + TimeStampString);

        try {
            try (BufferedReader br = new BufferedReader(new FileReader(FILENAME))) {                // create a buffer to read in filename.txt input
                String[] tokens = new String[10];                                                   // token array to set blockRecord input
                String InputLineStr;                                                                // this is our input
                String suuid;                                                                       // string version of UUID
                UUID idA;                                                                           // UUID

                int n = 0;

                while ((InputLineStr = br.readLine()) != null) {                                    // while we have inputto read (not null)

                    blockArray[n] = new BlockRecord();                                              // create a blockRecord

                    idA = UUID.randomUUID();                                                         // create a UUID (idA)
                    suuid = new String(UUID.randomUUID().toString());                                // set UUID to a string (suuid)

                    MessageDigest md = MessageDigest.getInstance("SHA-256");                        // get the bytes of suuid of instance "SHA-256"
                    md.update(suuid.getBytes());
                    byte byteData[] = md.digest();


                    StringBuffer sb = new StringBuffer();                                                       //read in the bytes and append to a string in hex format
                    for (int i = 0; i < byteData.length; i++) {
                        sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
                    }

                    String SHA256_UUIDString = sb.toString();                                                           // create the SHA256_UUID string from the Stringbuffer sb object

                    byte[] SignatureSuuidBytes = signData(SHA256_UUIDString.getBytes(), keyPair.getPrivate());             // get UUID signed by private key in byte format

                    boolean verified = verifySig(SHA256_UUIDString.getBytes(), keyPair.getPublic(), SignatureSuuidBytes);           // check if the signed UUID bytes is verified with the public key

                    String SHASignedUUID = getEncoder().encodeToString(SignatureSuuidBytes);                    // convert SHASignedUUID to base64

                    blockArray[n].setABlockID(suuid);                                                           //set UUID
                    blockArray[n].setASignedUUIDSHA256(SHASignedUUID);                                          //set SHASignedUUID with private Key
                    blockArray[n].setTimeStamp(TimeStampString);                                                // set timeStamp

                    blockArray[n].setASHA256String("SHA string goes here...");
                    blockArray[n].setASignedSHA256("Signed SHA string goes here...");


                    blockArray[n].setACreatingProcess("Process" + Integer.toString(pnum));                      // set creating process
                    blockArray[n].setAVerificationProcessID("To be set later...");                              // set this as a dummy string to be overwritten after the Work is complete

                    tokens = InputLineStr.split(" +");                                              // split our input to the prefined indices above and set the following into the blockrecord:
                    blockArray[n].setFSSNum(tokens[iSSNUM]);                                               // social security number
                    blockArray[n].setFFname(tokens[iFNAME]);                                                // first name
                    blockArray[n].setFLname(tokens[iLNAME]);                                                // last name
                    blockArray[n].setFDOB(tokens[iDOB]);                                                    // date of birth
                    blockArray[n].setGDiag(tokens[iDIAG]);                                                  // diagnosis
                    blockArray[n].setGTreat(tokens[iTREAT]);                                                // treatment
                    blockArray[n].setGRx(tokens[iRX]);                                                      // prescription


                    //create our SHA String from the input data (place in dataHasH later submission)
                    String inputData = blockArray[n].getFSSNum() + blockArray[n].getFFname() + blockArray[n].getFLname()+
                                       blockArray[n].getFDOB()+blockArray[n].getGDiag()+blockArray[n].getGTreat() + blockArray[n].getGRx() ;

                    // create SHA-256 hash of input data
                    MessageDigest mdInputData = MessageDigest.getInstance("SHA-256");
                    mdInputData.update(inputData.getBytes());

                    byte inputDataByte[] = mdInputData.digest();
                    StringBuffer sbInputData = new StringBuffer();
                    for (int i = 0; i < inputDataByte.length; i++) {
                        sbInputData.append(Integer.toString((inputDataByte[i] & 0xff) + 0x100, 16).substring(1));
                    }

                    //SHA256 Input Data String
                    String SHA256InputDataString = sbInputData.toString();                                  //write our SHA256 Hash buffer to String SHA256InputDataString

                    byte[] SignatureSHAInputDataBytes = signData(SHA256InputDataString.getBytes(), keyPair.getPrivate());                       // get bytes of Signed Input Data SHA String
                    boolean verifiedSHAString = verifySig(SHA256InputDataString.getBytes(), keyPair.getPublic(), SignatureSHAInputDataBytes);   //verified if it corresponds to public key sig


                    // conver the SignatureSHAInputDataBytes to base 64 encoding
                    String SHASignedInputDash = getEncoder().encodeToString(SignatureSHAInputDataBytes);

                    // add the SHA256 Input Data String
                    blockArray[n].setASHA256String(SHA256InputDataString);
                    // add the Signed SHA256 Input Data String
                    blockArray[n].setASignedSHA256(SHASignedInputDash);

                    n++;        // go to the next blockrecord
                }

            } catch (IOException e) {e.printStackTrace();}                  //catch and handle exceptions here
        } catch (Exception e) {e.printStackTrace();}
        return blockArray;                                                  // return our BlockRecord  (blockArray)
    }

    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {       // function definiion of signData for use in unverifiedBlockConsumer:  Code base from workA.java given by CE ( i know its in here twice but ran out of time to clean up code)
        Signature signer = Signature.getInstance("SHA1withRSA");                        // get Signature SHA1WithRSA instance
        signer.initSign(key);                                                           // initiate the signature with the privateKey given
        signer.update(data);                                                            // update the byte[] data given
        return (signer.sign());                                                         // return the signed hash
    }

    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {         // function definiion of verifySig for use in unverifiedBlockConsumer:  Code base from workA.java given by CE
        Signature signer = Signature.getInstance("SHA1withRSA");                                        // get Signature SHA1WithRSA instance
        signer.initVerify(key);                                                                         // initiate the signature verification with the publickey given
        signer.update(data);                                                                            // update the byte[] data given

        return (signer.verify(sig));                                                                // return the verification of hash boolean (true or false)
    }


    public static void MultiSendNewBlock(StringWriter block) {                              // function to MultiCast new BLockRecords when created in BlockInput
        Socket sock;
        PrintStream toServer;

        try{
            Thread.sleep(1000);                                                                 // sleep 1000 millis to settle program. Not sure if needed here since keys are settled but it seemed to help smooth the processes concurrency

            for(int i=0; i< numProcesses; i++){                                                     // send the block in form of StringWriter to all the processes
                sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);     //connect to the unverifiedBlockServerPorts for all processes and create a way to send output
                toServer = new PrintStream(sock.getOutputStream());
                toServer.println(block);                                            // send the multicast data
                toServer.flush();                                                   // clear our PrintStream buffer
                sock.close();                                                       //close the connection
            }
        }catch (Exception x) {x.printStackTrace ();}
    }


    public void MultiSendKeys(KeyPair keyPair) {                                                        //MultiSend keys method that takes in Keypair object
        Socket sock;                                                                                    // local definition of sock of type Socket
        PrintStream toServer;                                                                           // local definition of toServer of type PrintStream

        try{
            for(int i=0; i< numProcesses; i++){                                                         // for loop to send public keys to their respective servers
                sock = new Socket(serverName, (Ports.KeyServerPortBase+i));                             // open up new connection to the KeyPortServers based on PID
                toServer = new PrintStream(sock.getOutputStream());                                     // open up new OutputStream to this sock and initialized a PrintStream object "toServer"
                toServer.println(PID);                                                                  // send the Process ID to the KeyPortServers

                RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();                            //referred to java 8 docs with RSAPublicKey: https://docs.oracle.com/javase/8/docs/api/java/security/spec/RSAPublicKeySpec.html
                BigInteger modulus = publicKey.getModulus();                                            // get the modulus of type BigInteger
                BigInteger publicExponent = publicKey.getPublicExponent();                              // get the publicExponent of type BigInteger
                toServer.println(modulus);                                                              // send the modulus to the KeyPortServers
                toServer.println(publicExponent);                                                       // send the publicExponent to the KeyPortServers

                toServer.flush();                                                                       // clear the out buffer
                sock.close();                                                                           // close the current connection only
            }
            Thread.sleep(1000);                                                                   // sleep a 1000 milliseconds to allow keys to reach their destinations safely
        }catch (Exception x) {x.printStackTrace ();}                                                    // catch exceptions and print stack trace if caught
    }

    public static void main(String args[]) throws Exception {                           //Blockchain.java main
        int q_len = 8;                                                                  // number of queued requests set to 8
        int PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]);                    // set PID to the argument input.  If nothing is input, set PID to 0

        System.out.println("JeffChain Booting Up: control by Jeff Wiand-c to quit.\n");            // Send message that to console that we are starting up
        System.out.println("Using processID " + PID + "\n");                                        // send the process id being used

        ProcessBlock[] PBlock = new ProcessBlock[4];                                     // create new ProcessBlock object to store process information per process (PID). pass to all constructors

        final BlockingQueue<String> queue = new PriorityBlockingQueue<>();              // create instance of BlockingQueue to hold string of blocks to add/consume later
        new Ports().setPorts(PID);                                                      // create an instance of Ports, pass the PID, and set the Ports for communication / multicasting

        KeyPair keyPair = new Blockchain(PID).generateKeyPair(999+PID);            // generate a Keypair for each process

        new Thread(new PublicKeyServer(PBlock)).start();                                  // start a new thread for PublicKeyServer and pass it PBlock, then initiate it
        new Thread(new UnverifiedBlockServer(queue,PID, PBlock)).start();                 // start a new thread for UnverifiedBlockServer and pass it our queue, PID, and PBlock, then initiate it
        new Thread(new BlockchainServer()).start();                                       // start a new thread for BlockchainServer and pass it nothing, then initiate it
        new Thread(new BlockLedgerServer()).start();                                      // start a new thread for BlockLedgerServer and pass it nothing, then initiate it
        try{Thread.sleep(1000);}catch(Exception e){}                                // sleep for 1000 millis to let server's boot up

        new Blockchain(PID).MultiSendKeys(keyPair);                                         // initiate the multicast of keys

        try{Thread.sleep(1000);}catch(Exception e){}                                // sleep for 1000 millis to let keys reach their servers

        PublicKey publicKey0 = PBlock[0].getPubKey();                                       // set the publicKeys for use in verification later (future submission)
        PublicKey publicKey1 = PBlock[1].getPubKey();
        PublicKey publicKey2 = PBlock[2].getPubKey();

        System.out.println("Got PubKey of P" + PBlock[0].getProcessID() + ": " + publicKey0.getEncoded());      //Print the public keys for the corresponding process id's (given we are running processes. any other number of processes will break the main)
        System.out.println("Got PubKey of P" + PBlock[1].getProcessID() + ": " +publicKey1.getEncoded());       // fix the variable process id number for future submissions
        System.out.println("Got PubKey of P" + PBlock[2].getProcessID() + ": " +publicKey2.getEncoded());


        if(publicKey0 == publicKey1 && publicKey0==publicKey2 && publicKey1==publicKey2){               // check the all the public keys are different
            System.out.println("String version of Public Keys ARE equal");
        }else {
            System.out.println("String version of Public Keys ARE NOT equal");
        }

        BlockRecord[] blockRecord = new Blockchain(PID).BlockInput(keyPair);                        // Multicast some new unverified blocks out to all servers as data

        int indexCount = 0;                                                                         // count how many blockrecords have been added
        while(blockRecord[indexCount]!=null){
            indexCount++;
        }

        for(int i=0;i<indexCount;i++){                                                              // marshal the blockRecords to all the server processes
            String XMLString = Marshaller(blockRecord,i);
        }

        try{Thread.sleep(1000);}catch(Exception e){}                                        // sleep for 1000 millis to fill up the blocking queue


        new Thread(new UnverifiedBlockConsumer(queue, PID, keyPair, PBlock)).start();           // start a new thread for UnverifiedBlockConsumer and pass it our queue, PID, keyPair and PBlock, then initiate it

        Thread.sleep(10000);                                                            // sleep for 1000 millis to start consuming up the blocking queue

        while(queue.size()!=0){                                                               // while the queue is still full of blocks: Do this to make sure all the credit is assigned correctly
            System.out.println("queue length = " + queue.size());
            System.out.println("More blocks to consume");
            Thread.sleep(10000);                                                        // sleep for 1000 millis
        }

        System.out.println("Credit for P" + PBlock[PID].getProcessID() +"= " +PBlock[PID].getCredit());               // display credit for current process. Will multicast this in later version
    }
}






























