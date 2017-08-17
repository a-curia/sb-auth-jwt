package com.dbbyte.security.auth.jwt.verifier;

/**
 * 
 */
public interface TokenVerifier {
    public boolean verify(String jti);
}
