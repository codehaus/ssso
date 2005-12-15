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
 * A new SSO system will implement this interface to describe a user token
 * 
 * @author drand
 * 
 */
public interface ISimpleSSOToken {

    /**
     * The token is been correctly formatted
     * 
     * @return
     */
    public boolean isValid();

    /**
     * Are we still in the time period specified by the token?
     * 
     * @return
     */
    public boolean isExpired();

    /**
     * The fully qualified name of the user represented by the token
     * 
     * @return
     */
    public String getDistinguishedName();

    /**
     * A string version of the token that can be passed between applications.
     * For example in a cookie.
     * 
     * @return
     */
    public String getEncodedToken();

    /**
     * The date this token was created
     * 
     * @return
     */
    public Date getCreationDate();

    /**
     * The date this token is valid until
     * 
     * @return
     */
    public Date getExpiresDate();

    /**
     * May be null. The name the user typed to login. This will often be
     * different from the distinguishedName.
     * 
     * @return
     */
    public String getUsername();

    /**
     * May be null. The email address of the user.
     * 
     * @return
     */
    public String getEmail();

}
