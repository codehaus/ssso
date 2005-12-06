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
package org.codehaus.ssso.provider;

import java.io.IOException;

import org.codehaus.ssso.token.ISimpleSSOToken;

/**
 * ISSOTokenProvider implementations return ISimpleSSOToken objects credentials
 *
 * @author drand
 *
 */
public interface ISSOTokenProvider {

    /**
     * AuthenticationException is thrown when a user can't be authenticated.
     *
     * @author drand
     *
     */
    public class AuthenticationException extends RuntimeException {

        AuthenticationException(String message) {
            super(message);
        }

        AuthenticationException(Throwable throwable) {
            super(throwable);
        }
    }

    /**
     * Tries to log in a user based on name and password. If no exception is
     * thrown the authentication was successful.
     *
     * @throws IOException
     *
     * @throws AuthenticationException
     *             If the user could not be authenticated.
     */
    public abstract ISimpleSSOToken authenticate(String user, String password);

    public abstract ISimpleSSOToken authenticate(String tokenString);

}