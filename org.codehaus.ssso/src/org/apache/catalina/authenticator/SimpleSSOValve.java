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
package org.apache.catalina.authenticator;

import java.io.IOException;
import java.security.Principal;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.realm.SimpleSSORealm;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.ssso.provider.ISSOTokenProvider;
import org.codehaus.ssso.provider.SimpleSSOPrincipal;
import org.codehaus.ssso.provider.ISSOTokenProvider.AuthenticationException;
import org.codehaus.ssso.token.ISimpleSSOToken;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * Interacts with the SimpleSSORealm to ensure ltpatoken cookie creation and
 * removal. It manipulates the session and/or request in the following specific
 * cases.
 * 
 * <ul>
 * <li>User has a token cookie from a registered ISSOTokenProvider and has just
 * hit Tomcat</li>
 * <li>User has just used the Tomcat SimpleSSORealm to authenticate but has no
 * Cookie yet</li>
 * <li>User has a valid Tomcat session but has logged out from their SSO
 * provider</li>
 * </ul>
 * 
 * @author drand
 * 
 */
public class SimpleSSOValve extends ValveBase {

    private final static Log log = LogFactory.getLog(SimpleSSOValve.class);

    // **********************
    // Bean fields
    // **********************
    /**
     * Spring bean implementing ISSOTokenProvider
     */
    protected String ssoTokenCookieName;

    /**
     * Domain the cookie is valid in.. eg. ".codehaus.org"
     */
    protected String ssoTokenDomain;

    /**
     * Encoding used for signin form parameters.
     */
    protected String signinFormEncoding;

    /**
     * Descriptive information about this Valve implementation.
     */
    protected static String info = "org.apache.catalina.authenticator.SimpleSSOValve";

    /**
     * TODO Make this valve compatible with our one. This didn't work straight
     * off.. Might be best to stop the use of Tomcats SingleSignOn valve
     * instead.
     */
    private SingleSignOn sso;

    // **********************
    // End of bean fields
    // **********************

    private ClassPathXmlApplicationContext ctx;

    private static final String LOGOUT_ACTION = "/j_security_logout";

    public SimpleSSOValve() {
        String[] paths = { "sssoContext.xml" };
        ctx = new ClassPathXmlApplicationContext(paths);
    }

    /**
     * This is the main method. The container will call these in order
     * 
     * @see org.apache.catalina.Valve#invoke(org.apache.catalina.Request,
     *      org.apache.catalina.Response, org.apache.catalina.ValveContext)
     */
    public void invoke(Request request, Response response) throws IOException,
            ServletException {

        log.debug("Invoking SimpleSSOValve");

        Realm _realm = this.getContainer().getRealm();
        if (_realm == null || !(_realm instanceof SimpleSSORealm)) {
            log
                    .error("Unable to find Realm or Realm is not an instance of SimpleSSORealm. The SimpleSSOValve will be disabled.");
            getNext().invoke(request, response);
            return;
        }
        SimpleSSORealm realm = (SimpleSSORealm) _realm;

        if (signinFormEncoding == null) {
            log
                    .error("signinFormEncoding property not set. This valve will be disabled.");
            getNext().invoke(request, response);
            return;
        }

        if (ssoTokenDomain == null) {
            log
                    .error("ssoTokenDomain property not set. This valve will be disabled.");
            getNext().invoke(request, response);
            return;
        }

        if (ssoTokenCookieName == null) {
            log
                    .error("ssoTokenCookieName property not set. This valve will be disabled.");
            getNext().invoke(request, response);
            return;
        }

        if (false) {
            // TODO. Disable valve if the URI does not match the ssoTokenDomain
        }

        HttpServletRequest sreq = (HttpServletRequest) request.getRequest();
        HttpServletResponse sres = (HttpServletResponse) response.getResponse();

        sreq.setCharacterEncoding(signinFormEncoding);
        String requestURI = sreq.getRequestURI();

        // Is this the username/password POST?
        boolean loginAction = requestURI.endsWith(Constants.FORM_ACTION);
        boolean logoutAction = requestURI
                .endsWith(SimpleSSOValve.LOGOUT_ACTION);

        // Is this the redirect after successful username/password POST?
        boolean postAuthentication = matchRequest(request);

        // Get our SSOTokenProvider
        ISSOTokenProvider tokenProvider = realm.getSSOTokenProvider();

        // Get our SSO token if we have one
        Cookie cookie = getSimpleSSOCookie(sreq, getSsoTokenCookieName());
        ISimpleSSOToken token = null;
        try {
            if (cookie != null)
                token = tokenProvider.authenticate(cookie.getValue());
        } catch (Exception e) {
            // Cookie is a bad format
            log.debug("Token: " + cookie.getValue());
            log.error("Exception reading token cookie. ", e);

            getNext().invoke(request, response);
            return;
        }

        // Try and find a principal in the session..
        Session session = request.getSessionInternal(false);
        Principal userPrincipal = null;
        if (session != null)
            userPrincipal = session.getPrincipal();

        // Or saved as a note by the form authenticator
        if (userPrincipal == null)
            userPrincipal = getPostAuthPrincipalFromNote(session);

        SimpleSSOPrincipal principal = null;
        if (userPrincipal instanceof SimpleSSOPrincipal)
            principal = (SimpleSSOPrincipal) userPrincipal;

        // *** Setup finished. Now process different cases

        // Case - User is attempting authentication using the FormAuthenticator
        // Action - Do nothing
        if (loginAction) {
            log.info("Authentication attempted");
            getNext().invoke(request, response);
            return;
        }

        // Case - A successful authentication has just occurred
        // Action - Add the cookie
        if (postAuthentication && principal != null) {

            log.info("Post authentication. Adding token to response for "
                    + principal.getName());

            // Get a token from the principal
            token = realm.getSSOTokenProvider().authenticate(
                    principal.getPassword());

            addTokenCookie(sres, token, getSsoTokenCookieName(),
                    getSsoTokenDomain());
            log.info("Added ltpatoken to response");
            log.debug("Token value: " + token.toString());

            getNext().invoke(request, response);
            return;

        }

        // Case - User has just hit Tomcat with a valid SSO token
        // Action - Simulate an authentication
        if (principal == null && token != null && token.isExpired() == false) {

            // Authenticate and register our new session
            log.info("Authenticating from token. User "
                    + token.getDistinguishedName());
            session = request.getSessionInternal(true);
            principal = (SimpleSSOPrincipal) realm.authenticate(token);

            if (principal != null) {
                log.info("Authentication succeeded");
                register(request, response, principal, Constants.FORM_METHOD,
                        token.getDistinguishedName(), token.getEncodedToken());
            } else
                log.info("Authentication failed. Token may be invalid");

            getNext().invoke(request, response);
            return;
        }

        // Case - User was logged out on a different server
        // Action - Logout out the local session as well
        if (principal != null && token == null) {

            log.info("Remote logout was detected");

            if (session == null)
                throw new ServletException("Session was null unexpectedly");
            session.expire();
            log.info("Logged out user " + principal.getName());

            getNext().invoke(request, response);
            return;
        }

        // Case - User was logged out on this server
        // Action - Logout out the local session and delete the token. Redirect
        // to the /webapp/
        if (principal != null && token != null && logoutAction) {

            log.info("Local logout");
            expireTokenCookie(sres, getSsoTokenCookieName(),
                    getSsoTokenDomain());

            if (session == null)
                throw new ServletException("Session was null unexpectedly");
            session.expire();
            log.info("Logged out user " + principal.getName());

            boolean redirect = true;
            String redirectStr = sreq.getParameter("redirect");
            if (redirectStr != null && redirectStr.equalsIgnoreCase("false"))
                redirect = false;

            if (redirect == true) {
                String redirectURI = request.getContext().getPath() + "/";
                sres.sendRedirect(redirectURI);
                // context.invokeNext(request, response);
            }
            return;
        }

        // Case - We have received a token that has expired
        // Action - Expire the session to force the user to login again.
        if (principal != null && token != null && token.isExpired() == true) {

            log.info("Token has expired. Logging user out "
                    + principal.getName());
            expireTokenCookie(sres, getSsoTokenCookieName(),
                    getSsoTokenDomain());

            log.debug("Creation:" + token.getCreationDate().toGMTString());
            log.debug("Expiry:" + token.getExpiresDate().toGMTString());
            log.debug("Now:" + (new Date()).toGMTString());

            if (session == null)
                throw new ServletException("Session was null unexpectedly");
            session.expire();
            log.info("Logged out user " + principal.getName());

            getNext().invoke(request, response);
            return;

        }

        if (log.isDebugEnabled()) {
            log.debug("Request URI: " + requestURI);
            if (principal != null)
                log.debug("Username: " + principal.getName());
            else
                log.debug("No principal");
            if (token != null)
                log.debug("Token: " + token.toString());
            else
                log.debug("No token");

        }

        // We didn't need to do anything. Invoke the next Valve in our pipeline
        getNext().invoke(request, response);
        return;

    }

    /**
     * @param session
     */
    private Principal getPostAuthPrincipalFromNote(Session session) {

        if (session == null)
            return null;

        Object principal = session.getNote(Constants.FORM_PRINCIPAL_NOTE);

        if (principal != null)
            return (Principal) principal;
        return null;

    }

    public String getInfo() {
        return info;
    }

    public static Cookie getSimpleSSOCookie(HttpServletRequest hreq,
            String singleSignOnCookieName) {
        Cookie cookies[] = hreq.getCookies();
        if (cookies == null)
            cookies = new Cookie[0];
        Cookie cookie = null;
        for (int i = 0; i < cookies.length; i++) {
            if (singleSignOnCookieName.equals(cookies[i].getName())) {
                cookie = cookies[i];
                break;
            }
        }
        return cookie;
    }

    public static void addTokenCookie(HttpServletResponse hres,
            ISimpleSSOToken token, String singleSignOnCookieName,
            String tokenDomain) {
        Cookie cookie = new Cookie(singleSignOnCookieName, token.toString());
        cookie.setPath("/");
        cookie.setDomain(tokenDomain);
        hres.addCookie(cookie);
    }

    public static void expireTokenCookie(HttpServletResponse hres,
            String singleSignOnCookieName, String tokenDomain) {
        Cookie cookie = new Cookie(singleSignOnCookieName, "");
        cookie.setPath("/");
        cookie.setDomain(tokenDomain);
        cookie.setMaxAge(0);
        hres.addCookie(cookie);
    }

    /***************************************************************************
     * Code copied verbatim from the AuthenticatorBase or FormAuthenticator
     * 
     * 
     */

    /**
     * Does this request match the saved one (so that it must be the redirect we
     * signalled after successful authentication?
     * 
     * @param request
     *            The request to be verified
     */
    protected boolean matchRequest(Request request) {

        // Has a session been created?
        Session session = request.getSessionInternal(false);
        if (session == null)
            return (false);

        // Is there a saved request?
        SavedRequest sreq = (SavedRequest) session
                .getNote(Constants.FORM_REQUEST_NOTE);
        if (sreq == null)
            return (false);

        // Is there a saved principal?
        if (session.getNote(Constants.FORM_PRINCIPAL_NOTE) == null)
            return (false);

        // Does the request URI match?
        String requestURI = request.getRequestURI();
        if (requestURI == null)
            return (false);
        return (requestURI.equals(request.getRequestURI()));

    }

    /**
     * Register an authenticated Principal and authentication type in our
     * request, in the current session (if there is one), and with our
     * SingleSignOn valve, if there is one. Set the appropriate cookie to be
     * returned.
     * 
     * @param request
     *            The servlet request we are processing
     * @param response
     *            The servlet response we are generating
     * @param principal
     *            The authenticated Principal to be registered
     * @param authType
     *            The authentication type to be registered
     * @param username
     *            Username used to authenticate (if any)
     * @param password
     *            Password used to authenticate (if any)
     */
    protected void register(Request request, Response response,
            Principal principal, String authType, String username,
            String password) {

        // Cache the authentication information in our request
        request.setAuthType(authType);
        request.setUserPrincipal(principal);

        Session session = request.getSessionInternal(false);
        // Cache the authentication information in our session, if any
        // if (cache) {
        if (true) {
            if (session != null) {
                session.setAuthType(authType);
                session.setPrincipal(principal);
                if (username != null)
                    session.setNote(Constants.SESS_USERNAME_NOTE, username);
                else
                    session.removeNote(Constants.SESS_USERNAME_NOTE);
                if (password != null)
                    session.setNote(Constants.SESS_PASSWORD_NOTE, password);
                else
                    session.removeNote(Constants.SESS_PASSWORD_NOTE);
            }
        }

        // Construct a cookie to be returned to the client
        if (sso == null)
            return;

        // Only create a new SSO entry if the SSO did not already set a note
        // for an existing entry (as it would do with subsequent requests
        // for DIGEST and SSL authenticated contexts)
        String ssoId = (String) request.getNote(Constants.REQ_SSOID_NOTE);
        if (ssoId == null) {
            // Construct a cookie to be returned to the client
            HttpServletResponse hres = (HttpServletResponse) response
                    .getResponse();
            // TODO Make Tomcat SSO compatible with SimpleSSO. Removed this line
            // cause it doesn't compile.
            // ssoId = generateSessionId();
            Cookie cookie = new Cookie(Constants.SINGLE_SIGN_ON_COOKIE, ssoId);
            cookie.setMaxAge(-1);
            cookie.setPath("/");
            hres.addCookie(cookie);

            // Register this principal with our SSO valve
            sso.register(ssoId, principal, authType, username, password);
            request.setNote(Constants.REQ_SSOID_NOTE, ssoId);

        } else {
            // Update the SSO session with the latest authentication data
            sso.update(ssoId, principal, authType, username, password);
        }

        // Fix for Bug 10040
        // Always associate a session with a new SSO reqistration.
        // SSO entries are only removed from the SSO registry map when
        // associated sessions are destroyed; if a new SSO entry is created
        // above for this request and the user never revisits the context, the
        // SSO entry will never be cleared if we don't associate the session
        if (session == null)
            session = request.getSessionInternal(true);
        sso.associate(ssoId, session);

    }

    /***************************************************************************
     * Properties
     * 
     * 
     */

    public String getSigninFormEncoding() {
        return signinFormEncoding;
    }

    public void setSigninFormEncoding(String signinFormEncoding) {
        this.signinFormEncoding = signinFormEncoding;
    }

    public String getSsoTokenCookieName() {
        return ssoTokenCookieName;
    }

    public void setSsoTokenCookieName(String ssoTokenProviderName) {
        this.ssoTokenCookieName = ssoTokenProviderName;
    }

    public String getSsoTokenDomain() {
        return ssoTokenDomain;
    }

    public void setSsoTokenDomain(String ssoTokenDomain) {
        this.ssoTokenDomain = ssoTokenDomain;
    }

}