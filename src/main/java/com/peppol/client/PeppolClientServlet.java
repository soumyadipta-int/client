package com.peppol.client;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.File;
import java.io.StringWriter;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.annotation.Nonnull;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.busdox.servicemetadata.publishing._1.EndpointType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.unece.cefact.namespaces.sbdh.SBDMarshaller;
import org.unece.cefact.namespaces.sbdh.StandardBusinessDocument;
import org.w3c.dom.Document;

import com.helger.as2lib.client.AS2Client;
import com.helger.as2lib.client.AS2ClientRequest;
import com.helger.as2lib.client.AS2ClientResponse;
import com.helger.as2lib.client.AS2ClientSettings;
import com.helger.as2lib.crypto.ECryptoAlgorithm;
import com.helger.as2lib.disposition.DispositionOptions;
import com.helger.commons.GlobalDebug;
import com.helger.commons.exceptions.InitializationException;
import com.helger.commons.io.resource.ClassPathResource;
import com.helger.commons.io.streams.NonBlockingByteArrayOutputStream;
import com.helger.commons.xml.serialize.DOMReader;
import com.peppol.client.PeppolClientServlet;
import com.helger.peppol.sbdh.DocumentData;
import com.helger.peppol.sbdh.write.DocumentDataWriter;

import eu.europa.ec.cipa.busdox.identifier.IReadonlyParticipantIdentifier;
import eu.europa.ec.cipa.peppol.identifier.doctype.EPredefinedDocumentTypeIdentifier;
import eu.europa.ec.cipa.peppol.identifier.doctype.SimpleDocumentTypeIdentifier;
import eu.europa.ec.cipa.peppol.identifier.participant.SimpleParticipantIdentifier;
import eu.europa.ec.cipa.peppol.identifier.process.EPredefinedProcessIdentifier;
import eu.europa.ec.cipa.peppol.identifier.process.SimpleProcessIdentifier;
import eu.europa.ec.cipa.peppol.sml.ESML;
import eu.europa.ec.cipa.peppol.utils.ConfigFile;
import eu.europa.ec.cipa.smp.client.ESMPTransportProfile;
import eu.europa.ec.cipa.smp.client.SMPServiceCaller;
import eu.europa.ec.cipa.smp.client.SMPServiceCallerReadonly;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Random;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClient;
import com.amazonaws.services.sqs.model.CreateQueueRequest;
import com.amazonaws.services.sqs.model.DeleteMessageRequest;
import com.amazonaws.services.sqs.model.DeleteQueueRequest;
import com.amazonaws.services.sqs.model.Message;
import com.amazonaws.services.sqs.model.MessageAttributeValue;
import com.amazonaws.services.sqs.model.ReceiveMessageRequest;
import com.amazonaws.services.sqs.model.SendMessageRequest;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import org.oclc.purl.dsdl.svrl.SchematronOutputType;

import com.helger.schematron.ISchematronResource;
import com.helger.schematron.xslt.SchematronResourceSCH;

/**
 * Servlet implementation class PeppolClientServlet
 */
public class PeppolClientServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

    /**
     * Default constructor. 
     */
    public PeppolClientServlet() {
        // TODO Auto-generated constructor stub
    }
    
    /** The file path to the PKCS12 key store */
    private static final String PKCS12_CERTSTORE_PATH = "C:/workspace/as2-client/as2-client-data/test-ap.1peppol.net.p12";
    /** The password to open the PKCS12 key store */
    private static final String PKCS12_CERTSTORE_PASSWORD = "azdK53b88Xf724XpVi46ZV4759wATgl7EA6K9j2350Q77260dH";
    /** Your AS2 sender ID */
    private static final String SENDER_AS2_ID = "APP_1000000089";
   // private static final String SENDER_AS2_ID = "PEPPOL ACCESS POINT TEST CA";
    /** Your AS2 sender email address */
    private static final String SENDER_EMAIL = "peppol@example.org";
    /** Your AS2 key alias in the PKCS12 key store */
    private static final String SENDER_KEY_ALIAS = "app_1000000089 (peppol access point test ca)";
    //private static final String SENDER_KEY_ALIAS = "intghxeucoms";
    /** The PEPPOL document type to use. */
    private static final SimpleDocumentTypeIdentifier DOCTYPE = EPredefinedDocumentTypeIdentifier.INVOICE_T010_BIS4A_V20.getAsDocumentTypeIdentifier ();
    /** The PEPPOL process to use. */
    private static final SimpleProcessIdentifier PROCESS = EPredefinedProcessIdentifier.BIS4A_V20.getAsProcessIdentifier ();
    /** The PEPPOL transport profile to use */
    private static final ESMPTransportProfile TRANSPORT_PROFILE = ESMPTransportProfile.TRANSPORT_PROFILE_AS2;

    private static final Logger s_aLogger = LoggerFactory.getLogger (PeppolClientServlet.class);

    static
    {
      // Set Proxy Settings from property file. See:
      // http://download.oracle.com/javase/6/docs/technotes/guides/net/proxies.html
      for (final String sProperty : new String [] { "java.net.useSystemProxies",
                                                   "http.proxyHost",
                                                   "http.proxyPort",
                                                   "http.nonProxyHosts",
                                                   "https.proxyHost",
                                                   "https.proxyPort" })
      {
        final String sConfigValue = ConfigFile.getInstance ().getString (sProperty);
        if (sConfigValue != null)
        {
          System.setProperty (sProperty, sConfigValue);
          s_aLogger.info ("Set proxy property: " + sProperty + "=" + sConfigValue);
        }
      }

      // Sanity check
      if (!new File (PKCS12_CERTSTORE_PATH).exists ())
        throw new InitializationException ("The PKCS12 key store file '" + PKCS12_CERTSTORE_PATH + "' does not exist!");
      }

    /**
     * @param aCert
     *        Source certificate. May not be <code>null</code>.
     * @return The common name of the certificate subject
     * @throws CertificateEncodingException
     */
    @Nonnull
    private static String _getCN (@Nonnull final X509Certificate aCert) throws CertificateEncodingException
    {
      final X500Name x500name = new JcaX509CertificateHolder (aCert).getSubject ();
      final RDN cn = x500name.getRDNs (BCStyle.CN)[0];
      return IETFUtils.valueToString (cn.getFirst ().getValue ());
    }
    
    
	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		
		PrintWriter out = response.getWriter();
		
		out.println("Initializing...");
		
		// Must be first!
	    Security.addProvider (new BouncyCastleProvider ());

	    // Enable or disable debug mode
	    GlobalDebug.setDebugModeDirect (false);

	    IReadonlyParticipantIdentifier aReceiver;
	    String sTestFilename;
	    String sReceiverID = null;
	    String sReceiverKeyAlias = null;
	    String sReceiverAddress = null;
	    X509Certificate aReceiverCertificate = null;

	    out.println("Initialization ------------> [OK]");
	    
	   
	    //The ProfileCredentialsProvider will return your [default]
	    //credential profile by reading from the credentials file located at
	    //(~/.aws/credentials).
	    
	    AWSCredentials credentials = null;
	    try {
	    	out.println("Getting SQS Credentials...");
	    	
	        credentials = new ProfileCredentialsProvider().getCredentials();
	        
	       
	    } catch (Exception e) {
	    	out.println("Getting SQS Credentials ------------> [Failed:Wrong credential path]");
	    	out.println("redential---->"+e.getMessage());
	        throw new AmazonClientException(
	                "Cannot load the credentials from the credential profiles file. " +
	                "Please make sure that your credentials file is at the correct " +
	                "location (~/.aws/credentials), and is in valid format.",
	                e);
	        
	    }
	    
	    
	    
	    out.println("SQS Credentials ------------> [OK]");
	    
	    
	    out.println("Validating SQS Credentials...");
	    
	    //Amazon sqs initializtion
	    AmazonSQS sqs = new AmazonSQSClient(credentials);
	    Region euWest1 = Region.getRegion(Regions.EU_WEST_1);
	    sqs.setRegion(euWest1);
	    String messageBody = "";
	    HashMap sqsOutboxData = new HashMap();
	    
	    ArrayList sqsArr = new ArrayList(); 
	    
	    out.println("SQS Credentials Validated ------------> [OK]");
	    	
		// Receive messages from SQS
	    String myQueueUrl = "https://sqs.eu-west-1.amazonaws.com/460371557461/1peppol-ap-test-outbox";
	    
	    out.println("Receiving SQS Messages From Outbox...");
	    
	    ReceiveMessageRequest receiveMessageRequest = new ReceiveMessageRequest(myQueueUrl);
	    receiveMessageRequest.setMaxNumberOfMessages(10);
	    List<Message> messages = sqs.receiveMessage(receiveMessageRequest.withMessageAttributeNames("All")).getMessages();
	       
	 	if(messages.size() > 0) {
	 		out.println("Message Received From Outbox ------------> [OK]");
	 		
	 		out.println("Getting Keystore...");
	 		
	 		final AS2ClientSettings aSettings = new AS2ClientSettings ();
		 	aSettings.setKeyStore (new File (PKCS12_CERTSTORE_PATH), PKCS12_CERTSTORE_PASSWORD);
		 	
		 	out.println("Validate Keystore ------------> [OK]");
		 	
		 	// Fixed sender
		 	aSettings.setSenderData (SENDER_AS2_ID, SENDER_EMAIL, SENDER_KEY_ALIAS);
	 		
		 	out.println("Set Sender data ------------> [OK]");
		 	
	 		
	 		int i = 0;
	 		for (Message message : messages) {
	 			
	           //if(i > 0)
	        	   //out.println("<------- For Next Receiver ------->");
	 			
	 			
	 	       messageBody = message.getBody();
	 	       HashMap sqsMessageData = new HashMap();
	 	       for (Entry<String, MessageAttributeValue> entry : message.getMessageAttributes().entrySet()) {
	 	          	   
	 	    	   String attrKey = entry.getKey();
	 	    	   String attrVal = entry.getValue().getStringValue();
	 	    	   
	 	    	   if((attrKey!=null || !attrKey.equals("")) && (attrVal!=null || !attrVal.equals("")))
	 	    		   sqsMessageData.put(entry.getKey(), entry.getValue().getStringValue());
	 	                
	 	       }
	 	       
	 	       if(sqsMessageData.size() > 0) {
	 	    	  String fromParticipant = (String) sqsMessageData.get("FromParticipantID");
		 	       String toParticipant = (String) sqsMessageData.get("ToParticipantID");
		 	       String fromAccount = (String) sqsMessageData.get("FromAccountName");
		 	           
		 	       out.println("To Participants ---------> "+toParticipant);
		 	           
		 	       aReceiver = SimpleParticipantIdentifier.createWithDefaultScheme (toParticipant);
		 	           
		 	       s_aLogger.info ("SMP lookup for " + aReceiver.getValue ());
		 	       
		 	       out.println("Initializing SMP Lookup For "+toParticipant);
		 	 	   // Query SMP
		 	       try {
		 	       	  final SMPServiceCaller aSMPClient = new SMPServiceCaller (aReceiver, ESML.PRODUCTION);
		 		 	  final EndpointType aEndpoint = aSMPClient.getEndpoint (aReceiver, DOCTYPE, PROCESS, TRANSPORT_PROFILE);
		 		 	  if (aEndpoint == null) {
		 		 		out.println("SMP Lookup ------------> [Failed: Failed to resolve endpoint for docType/process]");  
		 		 		throw new NullPointerException ("Failed to resolve endpoint for docType/process");
		 		 	  }
		 		 	        
		 		 	
		 		 	  // Extract from SMP response
		 		 	  if (sReceiverAddress == null)
		 		 		  sReceiverAddress = SMPServiceCallerReadonly.getEndpointAddress (aEndpoint);
		 		 	  if (aReceiverCertificate == null)
		 		 	   	  aReceiverCertificate = SMPServiceCallerReadonly.getEndpointCertificate (aEndpoint);
		 		 	  if (sReceiverID == null)
		 		 	   	  sReceiverID = _getCN (aReceiverCertificate);
		 		 	
		 		 	  //out.println("SMP lookup begins");
		 		 	  //System.out.println("Receiver Address:"+sReceiverAddress);
		 		 	  //System.out.println("Receiver ID:"+sReceiverID);
		 		 	  // SMP lookup done
		 	 	      s_aLogger.info ("Receiver URL: " + sReceiverAddress);
		 	 	      s_aLogger.info ("Receiver DN:  " + sReceiverID);
		 		           
		 	 	      sReceiverKeyAlias = sReceiverID;
		 	       }
		 	       catch (Exception e) {
		 	    	  out.println("SMP Lookup ------------> [Failed: "+e+"]");
		 	       }
		 	 	      
		 		           
		 	       out.println("Set Receiver Settings...");
		 	       
		 	       if(sReceiverID != null && sReceiverKeyAlias != null && sReceiverAddress != "") {
		 	    	// Dynamic receiver
			 	 	   aSettings.setReceiverData (sReceiverID, sReceiverKeyAlias, sReceiverAddress);
			 	 	   aSettings.setReceiverCertificate (aReceiverCertificate);
			 	 	   
			 	 	   out.println("Receiver Settings ------------> [OK]");
			 	 	   
			 	 	   // AS2 stuff - no need to change anything in this block
			 	 	   aSettings.setPartnershipName (aSettings.getSenderAS2ID () + "_" + aSettings.getReceiverAS2ID ());
			 	 	   aSettings.setMDNOptions (new DispositionOptions ().setMICAlg (ECryptoAlgorithm.DIGEST_SHA1)
			 	 	                                                      .setMICAlgImportance (DispositionOptions.IMPORTANCE_REQUIRED)
			 	 	                                                      .setProtocol (DispositionOptions.PROTOCOL_PKCS7_SIGNATURE)
			 	 	                                                      .setProtocolImportance (DispositionOptions.IMPORTANCE_REQUIRED));
			 	 	   aSettings.setEncryptAndSign (null, ECryptoAlgorithm.DIGEST_SHA1);
			 	 	   aSettings.setMessageIDFormat ("OpenPEPPOL-$date.ddMMyyyyHHmmssZ$-$rand.1234$@$msg.sender.as2_id$_$msg.receiver.as2_id$");
			 	 	    
			 	 	   out.println("Set MDN ------------> [OK]");
			 	 	   
			 	 	   Random randomGenerator = new Random();
			 	 	   int randomInt = randomGenerator.nextInt(100000000);
			 	 	   //String fileName = SENDER_AS2_ID+"-"+sReceiverID+"-"+randomInt+".xml";
			 	 	   String fileName = "Invoice-client.xml";
			 	 	   sTestFilename = "C:/workspace/validation/schematron/xml-files/"+fileName;
			 	 	   File file = null;
			 	 	   //Writing xml file to xml folder
			 	 	   try {
			 	 		  
			 	 		   String content = messageBody;
			 	 
			 	 		   file = new File("C:/workspace/validation/schematron/xml-files/"+fileName);
			 	 
			 	 		   // if file doesnt exists, then create it
			 	 		   if (!file.exists()) {
			 	 			   file.createNewFile();
			 	 		   }
			 	 
			 	 		   FileWriter fw = new FileWriter(file.getAbsoluteFile());
			 	 		   BufferedWriter bw = new BufferedWriter(fw);
			 	 		   bw.write(content);
			 	 		   bw.close();
			 	 
			 	 		   //out.println("File Write Done");
			 	 
			 			} catch (IOException e) {
			 				e.printStackTrace();
			 			}
			 	 	   
			 	 	// 1. read XML
			 	 	   	Document aTestXML = null;
			 	 	   	StringWriter writer = null;
			 	 	   	try {
			 	 	   		aTestXML = DOMReader.readXMLDOM (new ClassPathResource (sTestFilename));
			 		 	    
			 		 	    // Converting xml to string
			 		 	    DOMSource domSource = new DOMSource(aTestXML);
			 		 	    writer = new StringWriter();
			 		 	    StreamResult result = new StreamResult(writer);
			 		 	    TransformerFactory tf = TransformerFactory.newInstance();
			 		 	    Transformer transformer = tf.newTransformer();
			 		 	    transformer.transform(domSource, result);
			 		 	    //System.out.println(writer.toString());
			 	 	   	}
			 	 	   	catch (Exception e) {
			         	  
			 	 	   	}
			 	 	    
			 	 	    
			 	 	    // 2. build SBD data
			 	 	    final DocumentData aDD = DocumentData.create (aTestXML.getDocumentElement ());
			 	 	    aDD.setSenderWithDefaultScheme (aReceiver.getValue ());
			 	 	    aDD.setReceiver (aReceiver.getScheme (), aReceiver.getValue ());
			 	 	    aDD.setDocumentType (DOCTYPE.getScheme (), DOCTYPE.getValue ());
			 	 	    aDD.setProcess (PROCESS.getScheme (), PROCESS.getValue ());

			 	 	    // 3. build SBD
			 	 	    final StandardBusinessDocument aSBD = new DocumentDataWriter ().createStandardBusinessDocument (aDD);
			 	 	    final NonBlockingByteArrayOutputStream aBAOS = new NonBlockingByteArrayOutputStream ();
			 	 	    if (new SBDMarshaller ().write (aSBD, new StreamResult (aBAOS)).isFailure ())
			 	 	      throw new IllegalStateException ("Failed to serialize SBD!");
			 	 	    aBAOS.close ();
			 	 	   
			 	 	   
			 	 	   	// Schematron validation
			 	 	   	try{
			 	 	   		File aSchematronFile = new File("C:/workspace/validation/schematron/OPENPEPPOL-UBL-T10.sch");
			 	 	   		
			 	 	   		final ISchematronResource aResSCH = SchematronResourceSCH.fromFile (aSchematronFile);
						  if (!aResSCH.isValidSchematron ()){
							  out.println("Schematron Validation ------------> [Failed: Invalid Schematron!]");
						      throw new IllegalArgumentException ("Invalid Schematron!");
						  }
						  else if(aResSCH.getSchematronValidity(new StreamSource (file)).isValid()){
							  	
							  	out.println("Schematron Validation ------------> [OK]");
							  	// 4. send message
					 	 	    final AS2ClientRequest aRequest = new AS2ClientRequest ("OpenPEPPOL AS2 message");
					 	 	    aRequest.setData (aBAOS.toByteArray ());
					 	 	    //System.out.println(aRequest);
					 	 	    
					 	 	    out.println("Sending Message...");
					 	 	    
					 	 	    final AS2ClientResponse aResponse = new AS2Client ().sendSynchronous (aSettings, aRequest);
					 	 	    
					 	 	    //System.out.println(aResponse.getAsString ());
					 	 	    //System.out.println(aResponse);
					 	 	    if (aResponse.hasException ()) {
					 	 	    	
					 	 	        
					 	 	        s_aLogger.info (aResponse.getAsString ());
					 	 	    }
					 	 	    else {
					 	 	    	
					 	 	    	out.println("Message Sent ------------> [OK]");
					 	 	    	
					 	 	    	out.println("Storing Message To Sent Queue...");
					 	 	        // Send a message
					 	 	        //out.println("Sending a message to Peppol SQS Queue.\n");
					 	 	        sqs.sendMessage(new SendMessageRequest("https://sqs.eu-west-1.amazonaws.com/460371557461/1peppol-ap-test-sent", writer.toString()));
					 	 	        out.println("Message Stored In Sent Queue ------------> [OK]");
					 	 	    }
						  }
						  else{
							  SchematronOutputType aSVRL = aResSCH.applySchematronValidationToSVRL(new StreamSource(file));
							  sqs.sendMessage(new SendMessageRequest("https://sqs.eu-west-1.amazonaws.com/460371557461/1peppol-ap-test-error", writer.toString()));
							  out.println("Schematron Validation ------------> [Failed: Invalid Xml]");
						  }

			 	 	   	}
			 	 	   	catch(Exception e){
			 				out.println(e.getMessage());
			 			}
		 	       }
		 	       else {
		 	    	  out.println("SMP Lookup ------------> [Failed: Invalid Receiver Id]");
		 	       }
		 	 	   
		 	       //--------------------//
	 	       }
	 	       else {
	 	    	  out.println("Receiver Or Sender Not Found");
	 	       }
	 	       
	 	 	   
	 	 	   i++;  
	 	 	    
	 	 	    
	 	        
	 	    }
	 	}
	 	else {
	 		out.println("Message Received From Outbox ------------> [Failed:No message exists.]");
	 	}
	    
	    	
	 	out.println("Done.");	
	 	s_aLogger.info ("Done");   
		
	}
	
}
