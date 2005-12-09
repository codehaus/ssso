/*
 * Copyright (c) 2005, Damon Rand
 * 
 * Derived from works by:
 * @author (parts) ingomar.otter@valtech.de
 * @author (parts) www.atlassian.com
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

package com.atlassian.seraph.auth;

import java.security.Principal;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.atlassian.seraph.config.SecurityConfig;
import com.atlassian.seraph.interceptor.LogoutInterceptor;
import com.opensymphony.user.EntityNotFoundException;
import com.opensymphony.user.User;
import com.opensymphony.user.UserManager;

/**
 * @author drand
 * 
 */
public class ConfluenceSimpleSSOAuthenticator extends DefaultAuthenticator {
    private static final Log log = LogFactory
            .getLog(ConfluenceSimpleSSOAuthenticator.class);

    protected String _cas_login_url;

    protected String _cas_logout_url;

    private SecurityConfig secConfig;

    public void init(Map params, SecurityConfig config) {
        super.init(params, config);
        _cas_login_url = config.getLoginURL();
        _cas_logout_url = config.getLogoutURL();

        this.secConfig = config;

    }

    /**
     * @return com.opensymphony.user.User
     * 
     */
    public Principal getUser(HttpServletRequest request,
            HttpServletResponse response) {

        // User has already signed in so Container will have a principal
        Principal containerPrincipal = request.getUserPrincipal();
        if (containerPrincipal == null) {
            log.info("No principal");
                    return null;
        }

        // This will be a distinguished name
        String user1 = request.getRemoteUser();
        String us = containerPrincipal.getName();
        us = "Damon Rand";
        log.info("getRemoteUser: " + user1);
        log.info("getUserPrincipal: " + containerPrincipal.toString());
        
        if (us != null) {
            log.debug("Container user:" + us);

            User user = null;

            try {
                user = UserManager.getInstance().getUser(us);
            } catch (EntityNotFoundException e) {
                log.error("Could not find user: " + us);
            }

            return user;

        } else {
            return super.getUser(request, response);
        }
    }

    public boolean login(HttpServletRequest request,
            HttpServletResponse response, String username, String password) {

        boolean loginSuccess = false;

        try {
            loginSuccess = login(request, response, username, password, false);
        } catch (AuthenticatorException e) {
            log.error("Problem loggin in: ", e);
            return loginSuccess;
        }
        return loginSuccess;
    }

    public boolean login(HttpServletRequest request,
            HttpServletResponse response, String username, String password,
            boolean cookie) throws AuthenticatorException {

        // User has already signed in so Container will have a principal
        Principal containerPrincipal = request.getUserPrincipal();

        // This will be a distinguished name
        String us = containerPrincipal.getName();
        us = "Damon Rand";

        log.info("Called login:" + username + " - " + us);

        if (us != null) {
            return true;
        } else {
            return super.login(request, response, username, password, cookie);
        }
    }

    public boolean logout(HttpServletRequest request,
            HttpServletResponse response) throws AuthenticatorException {

        log.info("Called logout");

        List interceptors = secConfig.getInterceptors(LogoutInterceptor.class);

        for (Iterator iterator = interceptors.iterator(); iterator.hasNext();) {
            LogoutInterceptor interceptor = (LogoutInterceptor) iterator.next();
            interceptor.beforeLogout(request, response);
        }

        // kill local session
        // Set the SimpleSSO session cookie to null.

        for (Iterator iterator = interceptors.iterator(); iterator.hasNext();) {
            LogoutInterceptor interceptor = (LogoutInterceptor) iterator.next();
            interceptor.afterLogout(request, response);
        }

        // FIXME: Seraph is supposed to call the redirect after executing this
        // method as long as
        // seraph-config.xml has an absolute logout.url parameter (includes
        // ://), does
        // not seem to be working however.

        return true;

    }

}