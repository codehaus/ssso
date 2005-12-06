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

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import org.codehaus.ssso.provider.ISSOTokenProvider;
import org.codehaus.ssso.token.ISimpleSSOToken;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Logger;
import org.apache.catalina.authenticator.SingleSignOn;

/**
 * Extends RealmBase to support the use of the lptatoken to authenticate
 * 
 * TODO Should we use the JAASRealm instead and implement this as a JAAS
 * LoginModule? TODO Should we detect for a token being used as a password and
 * just have one authenticate method, not two? TODO We should add a LDAP
 * connectionURL. Then we can query for roles once auth succeeds and add them to
 * the principal.
 * 
 * @author drand
 * 
 */
public class SimpleSSORealm extends RealmBase {

    // **********************
    // Bean fields
    // **********************

    /**
     * Spring bean implementing ISSOTokenProvider
     */
    protected String ssoTokenProviderName;

    /**
     * Address to form post to
     */
    protected String connectionURL;

    // **********************
    // End of bean fields
    // **********************

    private ClassPathXmlApplicationContext ctx;

    /**
     * Descriptive information about this Realm implementation.
     */
    protected static final String name = "SimpleSSORealm";

    public SimpleSSORealm() {
        String[] paths = { "sssoContext.xml" };
        ctx = new ClassPathXmlApplicationContext(paths);
    }

    /**
     * Validate using username and password, create a token and add it to the
     * returned Principal
     */
    public Principal authenticate(String username, String password) {

        if (debug > 1) {
            log("Called SimpleSSORealm authenticate");
            log("connectionURL: " + connectionURL);
            log("username: " + username);
            log("password: " + password);
        }

        URL loginURL = null;
        try {
            loginURL = new URL(connectionURL);
        } catch (MalformedURLException e) {
            log("connectionURL is invalid", e);
        }
        ISSOTokenProvider tokenProvider = (ISSOTokenProvider) ctx.getBean(this
                .getSsoTokenProviderName());

        ISimpleSSOToken token = tokenProvider.authenticate(username, password);

        // Check for successful authentication
        if (token == null)
            return null;

        // Pass to authenticate(
        Principal principal = authenticate(token);

        if (principal != null)
            log("Authentication succeeded for " + principal.getName());
        else
            log("Authentication failed");

        return principal;
    }

    /**
     * Given a valid token return a Principal
     * 
     * @param token
     * @return
     */
    public Principal authenticate(ISimpleSSOToken token) {

        // Check that a token is valid
        if (token.isValid()) {

            // Add roles if required
            List roles = new ArrayList();
            roles.add(new String("user")); // Hardcoded for Anthill

            SimpleSSOPrincipal principal = new SimpleSSOPrincipal(this, token
                    .getDistinguishedName(), token.getEncodedToken(), roles);

            return principal;
        } else
            return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.catalina.realm.RealmBase#getName()
     */
    protected String getName() {
        return name;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.catalina.realm.RealmBase#getPassword(java.lang.String)
     */
    protected String getPassword(String arg0) {
        return null;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.catalina.realm.RealmBase#getPrincipal(java.lang.String)
     */
    protected Principal getPrincipal(String arg0) {
        return null;
    }

    /**
     * Prepare for active use of the public methods of this Component.
     * 
     * @exception LifecycleException
     *                if this component detects a fatal error that prevents it
     *                from being started
     */
    public synchronized void start() throws LifecycleException {

        // Perform normal superclass initialization
        super.start();

    }

    /**
     * Gracefully shut down active use of the public methods of this Component.
     * 
     * @exception LifecycleException
     *                if this component detects a fatal error that needs to be
     *                reported
     */
    public synchronized void stop() throws LifecycleException {

        // Perform normal superclass finalization
        super.stop();

    }

    public String getConnectionURL() {
        return connectionURL;
    }

    public void setConnectionURL(String connectionURL) {
        this.connectionURL = connectionURL;
    }

    public String getSsoTokenProviderName() {
        return ssoTokenProviderName;
    }

    public void setSsoTokenProviderName(String ssoTokenProviderName) {
        this.ssoTokenProviderName = ssoTokenProviderName;
    }

    /**
     * Log a message on the Logger associated with our Container (if any)
     * 
     * @param message
     *            Message to be logged
     * @param throwable
     *            Associated exception
     */
    protected void log(String message, Throwable throwable) {

        if (debug > 0) {
            Logger logger = null;
            String name = null;
            if (container != null) {
                logger = container.getLogger();
                name = container.getName();
            }

            if (logger != null) {
                logger.log(getName() + "[" + name + "]: " + message, throwable);
            } else {
                System.out.println(getName() + "[" + name + "]: " + message);
                throwable.printStackTrace(System.out);
            }
        }
    }

}