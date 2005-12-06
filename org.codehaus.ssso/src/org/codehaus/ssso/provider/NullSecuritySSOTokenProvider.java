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
package org.codehaus.ssso.provider;

import org.codehaus.ssso.provider.ISSOTokenProvider.AuthenticationException;
import org.codehaus.ssso.token.DominoLtpaToken;
import org.codehaus.ssso.token.GenericToken;
import org.codehaus.ssso.token.ISimpleSSOToken;

public class NullSecuritySSOTokenProvider implements ISSOTokenProvider {

    private String secret;

    public NullSecuritySSOTokenProvider(String secret) {
        this.secret = secret;
    }

    public ISimpleSSOToken authenticate(String username, String password) {

        try {
            // Fetch token
            String tokenString = username + ":" + password;
            return new GenericToken(username, tokenString, secret);
        } catch (IllegalArgumentException e) {
            throw new AuthenticationException(e);
        }

    }

    public ISimpleSSOToken authenticate(String tokenString) {

        try {
            String[] arr = tokenString.split(":");
            return new GenericToken(arr[0], tokenString, secret);
        } catch (IllegalArgumentException e) {
            throw new AuthenticationException(e);
        }

    }

}
