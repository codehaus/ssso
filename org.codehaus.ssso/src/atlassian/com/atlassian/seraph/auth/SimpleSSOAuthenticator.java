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
import org.codehaus.ssso.ISimpleSSOPrincipal;

import bucket.container.ContainerManager;

import com.atlassian.seraph.config.SecurityConfig;
import com.atlassian.seraph.interceptor.LogoutInterceptor;
import com.atlassian.user.EntityException;
import com.atlassian.user.Group;
import com.atlassian.user.GroupManager;
import com.atlassian.user.User;
import com.atlassian.user.UserManager;

/**
 * 
 * 
 * @author drand
 * 
 */
public class SimpleSSOAuthenticator extends DefaultAuthenticator {

    private static final Log log = LogFactory
            .getLog(SimpleSSOAuthenticator.class);

    protected String _sso_login_url;

    protected String _sso_logout_url;

    private SecurityConfig secConfig;

    public void init(Map params, SecurityConfig config) {
        super.init(params, config);

        log.info("** Called init");

        _sso_login_url = config.getLoginURL();
        _sso_logout_url = config.getLogoutURL();

        this.secConfig = config;

    }

    public Principal getUser(HttpServletRequest request,
            HttpServletResponse response) {

        return super.getUser(request, response);

    }

    public boolean login(HttpServletRequest request,
            HttpServletResponse response, String username, String password) {

        boolean loginSuccess = false;

        try {
            loginSuccess = login(request, response, username, password, false);
        } catch (AuthenticatorException e) {
            log.error("Problem logging in: ", e);
            return loginSuccess;
        }
        return loginSuccess;
    }

    public boolean login(HttpServletRequest request,
            HttpServletResponse response, String username, String password,
            boolean cookie) throws AuthenticatorException {

        if (request.getSession().getAttribute(LOGGED_IN_KEY) != null
                && request.getSession().getAttribute(LOGGED_OUT_KEY) == null) {
            log.debug("Already logged in");
            return true;
        }

        // The SimpleSSOFilter should have provided access to the Container
        // principal
        ISimpleSSOPrincipal principal = (ISimpleSSOPrincipal) request
                .getAttribute(ISimpleSSOPrincipal.class.getCanonicalName());

        if (principal != null) {
            log
                    .debug("Found a ISimpleSSOPrincipal: "
                            + principal.getUsername());

            // See if the principal maps to a Confluence user
            UserManager userManager = (UserManager) ContainerManager
                    .getComponent("userManager");
            User user = null;
            try {
                user = userManager.getUser(principal.getUsername()
                        .toLowerCase());

                GroupManager groupManager = (GroupManager) ContainerManager
                        .getComponent("groupManager");

                Group group = groupManager.getGroup("confluence-users");
                if (!groupManager.hasMembership(group, user)) {
                    log.debug("Adding user to confluence-users: "
                            + user.getName());
                    groupManager.addMembership(group, user);
                }

                // TODO. We should compare email addresses to be sure we have
                // mapped to the right person. Or store the password in the
                // principal??

            } catch (EntityException e) {
                log.debug("getUser threw an exception: ", e);
            }

            if (user != null)
                log.debug("Found a user: " + user.getEmail());

            if (getRoleMapper().canLogin(user, request)) {
                log.debug("User can login");

                request.getSession().setAttribute(LOGGED_IN_KEY, user);
                request.getSession().setAttribute(LOGGED_OUT_KEY, null);
                return true;
            }

            log.debug("Attempting standard confluence login");
            return super.login(request, response, username, password, cookie);

        } else {
            // TODO. This doesn't work for some reason. Why not?
            log.debug("Attempting standard confluence login");
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
        // Redirect to logout location.
        // response.sendRedirect();

        // Tell confluence we logged out
        request.getSession().setAttribute(LOGGED_IN_KEY, null);
        request.getSession().setAttribute(LOGGED_OUT_KEY, Boolean.TRUE);

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