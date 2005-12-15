/*
 * Copyright (c) 2005, Amnesty International
 * Contributor(s): Damon Rand
 * 
 * Licensed subject to: http://ssso.codehaus.org/ContributorAgreement
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package org.codehaus.ssso.token;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

import cryptix.jce.provider.CryptixCrypto;
import cryptix.jce.provider.key.RawSecretKey;

/**
 * TODO Implement me!
 * 
 * Construct with a Base64 encoded LtpaToken and WS3DESData key and gain access
 * to the tokens fields. Construct with the tokens fields and the key and get
 * access to the LptaToken itself.
 * 
 * If you are using Domino compliant tokens this class will not work. Use the
 * DominoLtpaToken instead. You can distinguish which type of token you have
 * from the token header.
 * 
 * @author drand
 *  
 */
public class WebsphereLtpaToken {
    private Date creationDate;

    private Date expiresDate;

    private String username;

    /**
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws IllegalStateException
     *  
     */
    public WebsphereLtpaToken(String ltpaToken, String b64EncodedDESkey)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalStateException,
            IllegalBlockSizeException, BadPaddingException {
        super();

        if (true)
            throw new UnsupportedOperationException();

        // base64 decode the DES key
        byte[] theDESkey = Base64.decodeBase64(b64EncodedDESkey.getBytes());
        RawSecretKey key = new RawSecretKey("DES-EDE3", theDESkey);

        // Register our provider
        Provider cryptix = new CryptixCrypto();

        byte ltpa[] = Base64.decodeBase64(ltpaToken.getBytes());

        // Initialize a Cipher with our key
        Cipher cdes1 = Cipher.getInstance("TripleDES");
        cdes1.init(Cipher.DECRYPT_MODE, key);

        byte dcDES[] = cdes1.doFinal(ltpa);
        String ltpaDecodedString = new String(dcDES);

    }

    public Date getCreationDate() {
        return creationDate;
    }

    public Date getExpiresDate() {
        return expiresDate;
    }

    public String getUsername() {
        return username;
    }

    public static void main(String[] args) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalStateException, IllegalBlockSizeException,
            BadPaddingException {

        // Test the class
        String key = "???";
        String ltpaToken = "???";

        WebsphereLtpaToken token = new WebsphereLtpaToken(ltpaToken, key);

        System.out.println("-" + token.getCreationDate().toGMTString() + "-");
        System.out.println("-" + token.getExpiresDate().toGMTString() + "-");
        System.out.println("-" + token.getUsername() + "-");

    }

}