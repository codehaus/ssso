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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;

/**
 * Construct with a Base64 encoded LtpaToken and DominoSecret and gain access to
 * the tokens fields. Construct with the tokens fields and get access to the
 * LptaToken itself.
 * 
 * If you are using Domino compliant tokens this class will not work. Use the
 * DominoLtpaToken instead. You can distinguish which type of token you have
 * from the token header.
 * 
 * @author drand
 *  
 */
public class DominoLtpaToken implements ISimpleSSOToken {
    private Date creationDate;

    private Date expiresDate;

    private String distinguishedName;

    private String encodedToken;

    private boolean valid = false;

    private byte[] ltpa;

    private byte[] dominoSecret;

    private byte[] sha;

    private byte[] digest;

    /**
     *  
     */
    public DominoLtpaToken(String ltpaToken, String secret, String charset) {
        super();
        
        if (ltpaToken == null)
            throw new IllegalArgumentException("Token cannot be null");

        if (secret == null)
            throw new IllegalArgumentException("Secret cannot be null");

        this.dominoSecret = Base64.decodeBase64(secret.getBytes());
        this.ltpa = Base64.decodeBase64(ltpaToken.getBytes());
        this.encodedToken = ltpaToken;

        ByteArrayInputStream stream = new ByteArrayInputStream(ltpa);

        int usernameLength = ltpa.length - 40;
        if (usernameLength < 1 || usernameLength > 2000)
            throw new IllegalArgumentException("Invalid ltpaToken");
        
        byte header[] = new byte[4];
        byte creation[] = new byte[8];
        byte expires[] = new byte[8];
        byte username[] = new byte[usernameLength];
        sha = new byte[20];


        stream.read(header, 0, 4);

        if (header[0] != 0 || header[1] != 1 || header[2] != 2
                || header[3] != 3)
            throw new IllegalArgumentException("Invalid ltpaToken format");

        stream.read(creation, 0, 8);
        stream.read(expires, 0, 8);
        stream.read(username, 0, usernameLength);
        stream.read(sha, 0, 20);

        // Convert user bytes from Domino charset to unicode Java String
        char characters[] = new char[usernameLength];
        try {
            InputStreamReader isr = new InputStreamReader(
                    new ByteArrayInputStream(username), charset);
            isr.read(characters);
        } catch (Exception e) {
            e.printStackTrace();
        }
        distinguishedName = new String(characters);

        creationDate = new Date(Long.parseLong(new String(creation), 16) * 1000);
        expiresDate = new Date(Long.parseLong(new String(expires), 16) * 1000);

        // Create the digest
        ByteArrayOutputStream ostream = new ByteArrayOutputStream();
        try {
            ostream.write(header);
            ostream.write(creation);
            ostream.write(expires);
            ostream.write(username);
            ostream.write(dominoSecret);
            ostream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-1");
            md.reset();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        digest = md.digest(ostream.toByteArray());

        valid = MessageDigest.isEqual(digest, sha);
        
        if (!valid)
            throw new IllegalArgumentException(
                    "Token was not valid. Did you use the correct domino secret?");

    }

    public Date getCreationDate() {
        return creationDate;
    }

    public Date getExpiresDate() {
        return expiresDate;
    }

    public String getDistinguishedName() {
        return distinguishedName;
    }

    public String getEncodedToken() {
        return encodedToken;
    }

    /*
     * TODO We want to be able to get a short display name from the canonical
     * name
     *  
     */
    private String getUsername() {

        Pattern p = Pattern.compile("CN=(.*)/.*");
        Matcher m = p.matcher(distinguishedName);
        String username = null;
        if (m.matches() == true) {
            username = m.group(1);
        }

        return username;
    }

    public String toString() {
        return encodedToken;
    }

    /**
     * @return
     * @throws NoSuchAlgorithmException
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * @return
     */
    public boolean isExpired() {
        return expiresDate.before(new Date());
    }

}