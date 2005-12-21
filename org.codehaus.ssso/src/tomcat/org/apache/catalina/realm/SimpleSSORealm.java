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

import org.codehaus.ssso.SimpleSSOPrincipal;
import org.codehaus.ssso.provider.ISSOTokenProvider;
//import org.codehaus.ssso.provider.SimpleSSOPrincipal;
import org.codehaus.ssso.provider.ISSOTokenProvider.AuthenticationException;
import org.codehaus.ssso.token.ISimpleSSOToken;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.SimpleSSOValve;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Extends RealmBase to return a SimpleSSO token pm authentication
 * 
 * @author drand
 * 
 */
public class SimpleSSORealm extends RealmBase {

    private final static Log log = LogFactory.getLog(SimpleSSORealm.class);

    // **********************
    // Bean fields
    // **********************

    /**
     * Spring bean implementing ISSOTokenProvider
     */
    protected String ssoTokenProviderName;

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

        log
                .debug("Called SimpleSSORealm authenticate with username and password");
        ISSOTokenProvider tokenProvider = (ISSOTokenProvider) ctx.getBean(this
                .getSsoTokenProviderName());

        log.debug("username: " + username);
        log.debug("password: " + password);

        ISimpleSSOToken token = null;

        try {
            token = tokenProvider.authenticate(username, password);
        } catch (AuthenticationException e) {
            log.info("Authentication failed: ", e);
            return null;
        }

        // Pass to authenticate(
        Principal principal = authenticate(token);

        if (principal != null)
            log.info("Authentication succeeded for " + principal.getName());
        else
            log.info("Authentication failed");

        return principal;
    }

    /**
     * Given a valid token return a Principal
     * 
     * @param token
     * @return
     */
    public Principal authenticate(ISimpleSSOToken token) {

        if (token == null)
            throw (new IllegalArgumentException());

        // Check that a token is valid
        if (token.isValid()) {

            // Add roles if required
            List roles = new ArrayList();
            roles.add(new String("user")); // Hardcoded for Anthill

            SimpleSSOPrincipal principal = new SimpleSSOPrincipal(token
                    .getDistinguishedName(), token.getEncodedToken(), roles, token.getUsername(), token.getEmail());

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

    public String getSsoTokenProviderName() {
        return ssoTokenProviderName;
    }

    public void setSsoTokenProviderName(String ssoTokenProviderName) {
        this.ssoTokenProviderName = ssoTokenProviderName;
    }

    public ISSOTokenProvider getSSOTokenProvider() {
        ISSOTokenProvider tokenProvider = (ISSOTokenProvider) ctx.getBean(this
                .getSsoTokenProviderName());
        return tokenProvider;
    }

}