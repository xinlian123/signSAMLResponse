package saml;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Document;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import com.onelogin.saml2.util.Util;
import org.apache.xml.security.exceptions.XMLSecurityException;

public class response {
	public static void main(String[] args) throws UnsupportedEncodingException, XPathExpressionException, XMLSecurityException  {
		String id = "s2b47209af9e4281f1cfe16fc5745260a6f9062fd1";
		String ssoACS = "https://cabiqa.creditacceptance.com/saml2/sp/acs/post";
		String IDPIssuer = "openam";
		
		String ssoACS2 = "https://capsqa.creditacceptance.com/steps/saml/SSO";
		String IDPIssuer2 = "https://qaaccess.creditacceptance.com:8443/openam";
		
		String ssoACS3 = "https://dealerqa.creditacceptance.com/c/portal/saml/acs";
		String IDPIssuer3 = "https://qaaccess.creditacceptance.com:8443/openam";
		
		
		String FRapi = "<saml:Assertion xmlns:saml=\\\"urn:oasis:names:tc:SAML:2.0:assertion\\\" ID=\\\"s2d6dbcc56702c8812e4ad938d549fd4b88f2973e5\\\" IssueInstant=\\\"2019-05-01T19:28:49Z\\\" Version=\\\"2.0\\\">\\n<saml:Issuer>https://qaaccess.creditacceptance.com:8443/openam</saml:Issuer><ds:Signature xmlns:ds=\\\"http://www.w3.org/2000/09/xmldsig#\\\">\\n<ds:SignedInfo>\\n<ds:CanonicalizationMethod Algorithm=\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\"/>\\n<ds:SignatureMethod Algorithm=\\\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512\\\"/>\\n<ds:Reference URI=\\\"#s2d6dbcc56702c8812e4ad938d549fd4b88f2973e5\\\">\\n<ds:Transforms>\\n<ds:Transform Algorithm=\\\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\\\"/>\\n<ds:Transform Algorithm=\\\"http://www.w3.org/2001/10/xml-exc-c14n#\\\"/>\\n</ds:Transforms>\\n<ds:DigestMethod Algorithm=\\\"http://www.w3.org/2001/04/xmlenc#sha512\\\"/>\\n<ds:DigestValue>9leoma36/uajrynxRAOqk9W72nsy241WjYP6ZJcnvSEu65Ntm30kS49DBZneQQoqpveUymof//X4\\nCTPZEE+WFA==</ds:DigestValue>\\n</ds:Reference>\\n</ds:SignedInfo>\\n<ds:SignatureValue>\\nKEkSRJ/2vFskiVXSkFB8kHcu9JEiptf7QrXK5Yqe3iTrirYfL6gOtfH+JMiZdIx08PWW6c9XZkh0\\neZqxjQ6ADF43in1SaLCb9vVQRaQlid7VpvVI1EIBCj/8IOlEFfe9vquCgtkTDK936RvzEBuzNX22\\nyD06DD+swlIa4l+Fhrk=\\n</ds:SignatureValue>\\n<ds:KeyInfo>\\n<ds:X509Data>\\n<ds:X509Certificate>\\nMIICSjCCAbOgAwIBAgIEbt/YvzANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJVUzELMAkGA1UE\\nCBMCTUkxEzARBgNVBAcTClNvdXRoZmllbGQxCzAJBgNVBAoTAkZSMQwwCgYDVQQLEwNDQUMxDDAK\\nBgNVBAMTA1hpbjAeFw0xODAxMTUxNjEwMDVaFw0yMDAxMTUxNjEwMDVaMFgxCzAJBgNVBAYTAlVT\\nMQswCQYDVQQIEwJNSTETMBEGA1UEBxMKU291dGhmaWVsZDELMAkGA1UEChMCRlIxDDAKBgNVBAsT\\nA0NBQzEMMAoGA1UEAxMDWGluMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYxD9iYWrLYaEO\\nWr8NJMRDaL4/YqsWSuonJ0rkJkxpicpjEM6ui3L01NXi3WrmdITpNOrCB1aYE0pT9U1jkO1bKIsg\\nKyBi3HPcF/lUCvxrzEWGyW/vpUF6QS5KKJYxoMAja6dCkirEct8X9DLKu5q8Q9Q4TUDPWSAEG4zh\\n8IJ+owIDAQABoyEwHzAdBgNVHQ4EFgQUwLhIL0HDjGt4w5W+3ZE1RIXIggMwDQYJKoZIhvcNAQEL\\nBQADgYEAd6/QkKLq91N5qMUy7sMZHb1NR8LM3rE3diB2p54YpdoLbPe8kpDvDbz47kf4oua1KsVI\\nBfnhb4/YPCpOVOPPzBqg2WzMhvfiWsqTqhhrPJghjK8tINbVUD+wVNwCWfftQliqucwnw6vlBCQZ\\nbbEdBQNEDFDvvWd9ougyO84hQyU=\\n</ds:X509Certificate>\\n</ds:X509Data>\\n</ds:KeyInfo>\\n</ds:Signature><saml:Subject>\\n<saml:NameID Format=\\\"urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified\\\">xlian</saml:NameID><saml:SubjectConfirmation Method=\\\"urn:oasis:names:tc:SAML:2.0:cm:bearer\\\">\\n<saml:SubjectConfirmationData NotOnOrAfter=\\\"2019-05-01T19:38:49Z\\\" Recipient=\\\"https://capsqa.creditacceptance.com/steps/saml/SSO\\\"/></saml:SubjectConfirmation>\\n</saml:Subject><saml:Conditions NotBefore=\\\"2019-05-01T19:28:49Z\\\" NotOnOrAfter=\\\"2019-05-01T19:38:49Z\\\">\\n<saml:AudienceRestriction>\\n<saml:Audience>https://capsqa.creditacceptance.com/steps/saml/metadata</saml:Audience>\\n</saml:AudienceRestriction>\\n</saml:Conditions>\\n<saml:AuthnStatement AuthnInstant=\\\"2019-05-01T19:28:49Z\\\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name=\\\"AuthSource\\\"><saml:AttributeValue xmlns:xs=\\\"http://www.w3.org/2001/XMLSchema\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"xs:string\\\">2</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\\\"uid\\\"><saml:AttributeValue xmlns:xs=\\\"http://www.w3.org/2001/XMLSchema\\\" xmlns:xsi=\\\"http://www.w3.org/2001/XMLSchema-instance\\\" xsi:type=\\\"xs:string\\\">xlian</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>";
		 FRapi = FRapi.replace("\\n","\n");
		String assertion = FRapi.replace("\\","");
		
		String substr = "IssueInstant=\"";
		String[] parts = assertion.split(substr);
		String Issuetime = parts[1].substring(0,20);
		//System.out.println(assertion);
		
		response res = new response();
		
		String response2 ="<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\""+ id + "\" " + "Version=\"2.0\" IssueInstant=\"" + 
		Issuetime + "\" " + "Destination=\"" + ssoACS2 + "\"><saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"+ IDPIssuer2 +"</saml:Issuer><samlp:Status xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">\r\n" + 
				"<samlp:StatusCode xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\">\r\n" + 
				"</samlp:StatusCode>\r\n" + 
				"</samlp:Status>"+ assertion +"</samlp:Response>";
		//System.out.println(response2);
	
		byte[] encodedBytes = Base64.getEncoder().encode(response2.getBytes());
		String encodedResponse = new String(encodedBytes);
		
		//System.out.println(response2);			
		 
		String UTFsamlResponse = URLEncoder.encode(encodedResponse, "UTF-8")
				.replaceAll("\\+", "%20")
                .replaceAll("\\%21", "!")
                .replaceAll("\\%27", "'")
                .replaceAll("\\%28", "(")
                .replaceAll("\\%29", ")")
                .replaceAll("\\%7E", "~");
	
		res.unirest(UTFsamlResponse);
		res.SignResponse(response2);
	}	

	
//Post data back to application	
	public void unirest(String samlResponse) {
		try {
			HttpResponse<String> response = Unirest.post("https://capsqa.creditacceptance.com/steps/saml/SSO")
					  .header("Content-Type", "application/x-www-form-urlencoded")
					  .header("cache-control", "no-cache")
					  .body("SAMLResponse=" + samlResponse)
					  .asString();
			System.out.println(response.getBody());
		} catch (UnirestException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	
//Sign SAMLResonse	
	public void SignResponse(String unsignedSamlResponse) throws UnsupportedEncodingException, XPathExpressionException, XMLSecurityException{
		Document document = Util.loadXML(unsignedSamlResponse); //loads string to document
		
		//load private key and certificate
		X509Certificate cert = null;
		try {
			cert = Util.loadCert("-----BEGIN CERTIFICATE-----\r\n" + 
					"MIICSjCCAbOgAwIBAgIEbt/YvzANBgkqhkiG9w0BAQsFADBYMQswCQYDVQQGEwJV\r\n" + 
					"UzELMAkGA1UECBMCTUkxEzARBgNVBAcTClNvdXRoZmllbGQxCzAJBgNVBAoTAkZS\r\n" + 
					"MQwwCgYDVQQLEwNDQUMxDDAKBgNVBAMTA1hpbjAeFw0xODAxMTUxNjEwMDVaFw0y\r\n" + 
					"MDAxMTUxNjEwMDVaMFgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJNSTETMBEGA1UE\r\n" + 
					"BxMKU291dGhmaWVsZDELMAkGA1UEChMCRlIxDDAKBgNVBAsTA0NBQzEMMAoGA1UE\r\n" + 
					"AxMDWGluMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYxD9iYWrLYaEOWr8N\r\n" + 
					"JMRDaL4/YqsWSuonJ0rkJkxpicpjEM6ui3L01NXi3WrmdITpNOrCB1aYE0pT9U1j\r\n" + 
					"kO1bKIsgKyBi3HPcF/lUCvxrzEWGyW/vpUF6QS5KKJYxoMAja6dCkirEct8X9DLK\r\n" + 
					"u5q8Q9Q4TUDPWSAEG4zh8IJ+owIDAQABoyEwHzAdBgNVHQ4EFgQUwLhIL0HDjGt4\r\n" + 
					"w5W+3ZE1RIXIggMwDQYJKoZIhvcNAQELBQADgYEAd6/QkKLq91N5qMUy7sMZHb1N\r\n" + 
					"R8LM3rE3diB2p54YpdoLbPe8kpDvDbz47kf4oua1KsVIBfnhb4/YPCpOVOPPzBqg\r\n" + 
					"2WzMhvfiWsqTqhhrPJghjK8tINbVUD+wVNwCWfftQliqucwnw6vlBCQZbbEdBQNE\r\n" + 
					"DFDvvWd9ougyO84hQyU=\r\n" + 
					"-----END CERTIFICATE-----");
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		PrivateKey privateKey = null;
		try {
			privateKey = Util.loadPrivateKey("-----BEGIN PRIVATE KEY-----\r\n" + 
					"MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJjEP2JhasthoQ5a\r\n" + 
					"vw0kxENovj9iqxZK6icnSuQmTGmJymMQzq6LcvTU1eLdauZ0hOk06sIHVpgTSlP1\r\n" + 
					"TWOQ7VsoiyArIGLcc9wX+VQK/GvMRYbJb++lQXpBLkooljGgwCNrp0KSKsRy3xf0\r\n" + 
					"Msq7mrxD1DhNQM9ZIAQbjOHwgn6jAgMBAAECgYAoHmmy8Xh1XvdH6McBsaUlOs2z\r\n" + 
					"obriiNwDWktNrU0l7jzLVW+h4RdYesiM4q8fRHxfLjl0qS6xk2dSszoWqsnaXcTb\r\n" + 
					"iWWMMGvgrrHqnHtopei612KMo14pL3+t/LTYJw0NtV8s8Zoxn4AqTbcXQaZ1r33S\r\n" + 
					"xqRtosXbsio/u1w1kQJBAM/TyWcrKzMO0nIP7To8X/1l0qoN6zZIHakBAOGFZuYI\r\n" + 
					"zIi5aan6fnppMjIrY4RFwDpSfce+sSjl4oNY2wg3fzsCQQC8LTo0BNdtEFt2bKHY\r\n" + 
					"YV6utc6B+msJebfHRUk2XUb11oyPpm54b8SZZxIhJMPqgsrGRIwIXldgcSELOe7+\r\n" + 
					"19e5AkABZgJv8EltIYdm/xZwkuFuehXt0QQpLFkOvxP7cINdvudpcB3259mcB0Mw\r\n" + 
					"NTyJMlL10YJJKs5UYR+iFKH8ryrrAkA0X2ITmEVc1XCfRRzGXFM9zNvs0QV5XacI\r\n" + 
					"jwARYWSeh1gXovqcCn9tMoKZNuJQIpbNF8bhjWBENzg7J6ScyPYBAkAN7dwYp6uQ\r\n" + 
					"AJkdziz0Mlh5loH2oxMWzrOETBt/9OsKqMI5mpkIngzQ6H5Ck/6VXy++DngtEcF3\r\n" + 
					"LT4i3wdbbCVB\r\n" + 
					"-----END PRIVATE KEY-----");
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		String signedResponse = Util.addSign(document, privateKey, cert, null);
		System.out.println(signedResponse);	
	}
}