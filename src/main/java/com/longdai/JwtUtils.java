package com.longdai;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Date;

public class JwtUtils {

    private static final SecretKey SECRET_KEY;
    static {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyGen.init(256);
        SECRET_KEY = keyGen.generateKey();

    }

    public static String getJwtToken(Long userId) throws JOSEException, NoSuchAlgorithmException {
        // Generate 256-bit AES key for HMAC as well as encryption
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(userId + "")
                .expirationTime(new Date(1300819380 * 1000l))
                .claim("http://example.com/is_root", true)
                .build();



        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

        // Apply the HMAC
        JWSSigner signer = new MACSigner(SECRET_KEY);
        signedJWT.sign(signer);

        // Create JWE object with signed JWT as payload
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                        .contentType("JWT") // required to signal nested JWT
                        .build(),
                new Payload(signedJWT));

        jweObject.encrypt(new DirectEncrypter(SECRET_KEY));

        // Serialise to JWE compact form
        String jweString = jweObject.serialize();
        return jweString;
    }

    public static SignedJWT verifyJwtToken(String jweString) throws ParseException, JOSEException {
        // Parse the JWE string
        JWEObject jweObject = JWEObject.parse(jweString);

        // Decrypt with shared key
        jweObject.decrypt(new DirectDecrypter(SECRET_KEY));

        // Extract payload
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

        signedJWT.verify(new MACVerifier(SECRET_KEY));

//        assertNotNull("Payload not a signed JWT", signedJWT);

        // Check the HMAC
//        assertTrue(signedJWT.verify(new MACVerifier("privatekey")));

        // Retrieve the JWT claims...
//        assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
        return signedJWT;
    }
}
