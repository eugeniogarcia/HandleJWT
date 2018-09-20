package com.euge;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.CharBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;

@Component
public class handleJWT {
	
	//https://github.com/jwtk/jjwt
	
    public PublicKey loadPublicKey(String clave) {
    	try {
		    clave=clave.replace("-----BEGIN CERTIFICATE-----", "")
							    .replace("-----END CERTIFICATE-----", "")
							    .replaceAll("\\s", "");
		    
		    byte[] encodedCert;
			try {
				encodedCert = clave.getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				return null;
			}
		    byte[] decodedCert = Base64.getDecoder().decode(encodedCert);
		   
		    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		    InputStream in = new ByteArrayInputStream(decodedCert);
		    X509Certificate certificate = (X509Certificate)certFactory.generateCertificate(in);
		    
		    PublicKey publicKey = certificate.getPublicKey();
		    return publicKey;
    	}
    	catch (CertificateException ex) {
    		return null;
    	}
    	
	}
	
	//public static PrivateKey loadPrivateKey(InputStream fileStream) throws Exception {
    public PrivateKey loadPrivateKey(String clave) {
    	String privateKeyPEM;
        Reader reader = new StringReader(clave);
        
        try {
            StringBuilder stringBuilder = new StringBuilder();

            CharBuffer buffer = CharBuffer.allocate(2048);
            try {
				while (reader.read(buffer) != -1) {
				    buffer.flip();
				    stringBuilder.append(buffer);
				    buffer.clear();
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				return null;
			}
            privateKeyPEM = stringBuilder.toString();
        } finally {
            try {
				reader.close();
			} catch (IOException e) {
				return null;
			}
        }

        // strip of header, footer, newlines, whitespaces
        privateKeyPEM = privateKeyPEM
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        // decode to get the binary DER representation
        byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
        PrivateKey privateKey;
		try {
			privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDER));
		} catch (InvalidKeySpecException e) {
			return null;
		}
        return privateKey;
    }
    
	public String createJWT(Key key, SignatureAlgorithm algorithm_used,String name, String surname, String phone, String email,String locale, String Authlevel, String RegLevel, String subjectid ) {
		Calendar cal = Calendar.getInstance(); // creates calendar
	    cal.setTime(new Date()); // sets calendar time/date
	    cal.add(Calendar.HOUR_OF_DAY, 24000); // adds one hour
	    
		return  Jwts.builder()
				  .setSubject(subjectid)
//				  .claim("subjectid", name)
                  .claim("given_name", name)
                  .claim("family_name",surname)
                  .claim("phone_number", phone)
                  .claim("email", email)
                  .claim("locale", locale)
                  .claim("session_authlevel", Authlevel)                  
                  .claim("user_reglevel", RegLevel)
                  //Expires after one hour
                  .setExpiration(cal.getTime())
                  .setId(UUID.randomUUID().toString())
				  .signWith(algorithm_used, key)
				  .compact();
		}
	
		public boolean checkJWT(Key key, String miJwt) {
			try {
				Jwts.parser().setSigningKey(key).parseClaimsJws(miJwt);
				return true;
			}
			catch (SignatureException e) {
				return false;
			}
		}

}
