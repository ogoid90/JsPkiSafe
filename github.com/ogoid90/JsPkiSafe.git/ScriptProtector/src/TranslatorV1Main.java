import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import Decoder.BASE64Decoder;

public class TranslatorV1Main {

	public static final String P1_END_MARKER = "-----END RSA PRIVATE KEY";
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	
	public static void main(String[] args) {
		
		Scanner sc = new Scanner(System.in);
		String rsaKey;
		String cert;
		String html;
			
		while(true) {
	
			System.out.println("Insira a localização do ficheiro PEM com RSA chave privada:");
			rsaKey = sc.nextLine();
			System.out.println("");
			
			System.out.println("Insira a localização do ficheiro PEM com RSA chave pública:");
			cert = sc.nextLine();
			System.out.println("");
			
			System.out.println("Insira a localização do seu ficheiro HTML a assinar:");
			html = sc.nextLine();
			System.out.println("");
			
			try {
				signPage(rsaKey, html, cert);
				System.out.println("Ficheiro HTML assinado com sucesso.");
			} catch (IOException e) {
				System.out.println("Erro ao obter o ficheiro HTML.");
			} catch (Exception e) {
				System.out.println("Erro ao assinar o ficheiro HTML.");
			}
			
			sc.close();
			System.exit(0);
		}
	}

	private static void signPage(String rsaKey, String html, String cert) throws Exception {
		File pgehtml = new File(html);
		Document doc = Jsoup.parse(pgehtml, "UTF-8", "");
		
		Scanner sc = new Scanner(new File(cert));
		String certificte = "";
		while(sc.hasNextLine()){
		    certificte = sc.nextLine();                     
		}
		sc.close();
		
		Elements scripts = doc.getElementsByTag("script");
		
		if(null != scripts && scripts.size() > 0){
		
			PrivateKey privateKey = readPrivateKey(new File(rsaKey));
			Signature dsa = Signature.getInstance("SHA1withRSA");
			
			for (int i = 0; i < scripts.size(); i++) {
				
				Element script = scripts.get(i);
				script.attr("class", "js");
		        
				dsa.initSign(privateKey);
		        dsa.update(script.html().trim().getBytes());
		        byte[] signaux = dsa.sign();
		        
		        Element parent = script.parent();
				parent.appendElement("form").attr("name", "formSig"+i).attr("id", "formSig"+i);
				
				Element form = parent.getElementById("formSig"+i);
				form.prependElement("input").attr("type","hidden").attr("name","siggenerated"+i).attr("id","siggenerated"+i).attr("value", toHexString(signaux).toLowerCase());
				form.prependElement("input").attr("type","hidden").attr("name","cert"+i).attr("id","cert"+i).attr("value", certificte);
				form.append(script.outerHtml());
				
		        script.remove();
		    }
			
			String html2 = html.replace(".html", "");
			html2 = html2+"Signed.html";
			
			PrintWriter writer = new PrintWriter(html2, "UTF-8");
			writer.println(doc);
			writer.close();
			
		}
	}

	public static String toHexString(byte[] array) {
	    return DatatypeConverter.printHexBinary(array);
	}
	
	public static PrivateKey readPrivateKey(File keyFile) throws Exception {
	    // read key bytes
		FileInputStream in = new FileInputStream(keyFile);
		byte[] keyBytes = new byte[in.available()];
		in.read(keyBytes);
		in.close();

		String privateKey = new String(keyBytes, "UTF-8");
		privateKey = privateKey.replace("-----BEGIN RSA PRIVATE KEY-----", "");
		privateKey = privateKey.replace("-----END RSA PRIVATE KEY-----", "");
		
		BASE64Decoder decoder = new BASE64Decoder();
		keyBytes = decoder.decodeBuffer(privateKey);

		// generate private key
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPrivateCrtKeySpec keySpec = getRSAKeySpec(keyBytes);
		return keyFactory.generatePrivate(keySpec);
	}
	
	private static RSAPrivateCrtKeySpec getRSAKeySpec(byte[] keyBytes) throws IOException  {
    	
    	DerParser parser = new DerParser(keyBytes);
        
    	Asn1Object sequence = parser.read();
        if (sequence.getType() != DerParser.SEQUENCE)
        	throw new IOException("Invalid DER: not a sequence");
        
        parser = sequence.getParser();
        
        parser.read();
        BigInteger modulus = parser.read().getInteger();
        BigInteger publicExp = parser.read().getInteger();
        BigInteger privateExp = parser.read().getInteger();
        BigInteger prime1 = parser.read().getInteger();
        BigInteger prime2 = parser.read().getInteger();
        BigInteger exp1 = parser.read().getInteger();
        BigInteger exp2 = parser.read().getInteger();
        BigInteger crtCoef = parser.read().getInteger();
            
        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
        		modulus, publicExp, privateExp, prime1, prime2,
        		exp1, exp2, crtCoef);
        
        return keySpec;
    }  
	
}
