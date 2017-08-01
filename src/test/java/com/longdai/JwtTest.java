package com.longdai;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Assert;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

public class JwtTest {
    @Test
    public void get_jwt_token_then_verify_test() throws ParseException, JOSEException, NoSuchAlgorithmException {
        String jweString = JwtUtils.getJwtToken(12345L);
        SignedJWT signedJWT = JwtUtils.verifyJwtToken(jweString);
        Assert.assertEquals("12345", signedJWT.getJWTClaimsSet().getSubject());
    }
}
