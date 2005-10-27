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
package org.apache.catalina.realm;

import java.util.List;

import org.apache.catalina.Realm;

/**
 * Eventually we will extend this to handle Domino roles.
 * 
 * TODO Add role support. 
 * 
 * @author drand
 *  
 */
public class SimpleSSOPrincipal extends GenericPrincipal {

    private String dn;

    public SimpleSSOPrincipal(Realm realm, String distinguishedName, String password) {
        super(realm, distinguishedName, password);
    }

    public SimpleSSOPrincipal(Realm realm, String distinguishedName, String password,
            List roles) {
        super(realm, distinguishedName, password, roles);
    }

    public SimpleSSOPrincipal(String distinguishedName, String password, List roles) {
        super(distinguishedName, password, roles);
    }

}