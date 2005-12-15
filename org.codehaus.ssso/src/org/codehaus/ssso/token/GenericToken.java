/*
 * Copyright (c) 2005, Damon Rand
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

import java.util.Date;

/**
 * A GenericToken is a simple, insecure token where the secret is the same as
 * the password. The encoded form simply concats the username and password
 * together.
 * 
 * @author drand
 * 
 */
public class GenericToken implements ISimpleSSOToken {

    private String distName;

    private String token;

    private String secret;

    public GenericToken(String distName, String token, String secret) {
        if (distName == null)
            throw new IllegalArgumentException();

        if (token == null)
            throw new IllegalArgumentException();

        if (secret == null)
            throw new IllegalArgumentException();

        this.distName = distName;
        this.token = token;
        this.secret = secret;

        if (isValid() == false)
            throw new IllegalArgumentException("Token is invalid");
    }

    public boolean isValid() {

        String[] arr = token.split(":");

        if (arr.length == 2 && arr[1].equals(secret))
            return true;
        else
            return false;
    }

    public boolean isExpired() {
        return false;
    }

    public String getDistinguishedName() {
        return distName;
    }

    public String getEncodedToken() {
        return token;
    }
    
    public String toString(){
        return getEncodedToken();
    }

    public Date getCreationDate() {
        return new Date("1/1/2000");
    }

    public Date getExpiresDate() {
        return new Date("1/1/2025");
    }

    public String getUsername() {
        // TODO Auto-generated method stub
        return null;
    }

    public String getEmail() {
        // TODO Auto-generated method stub
        return null;
    }

}
