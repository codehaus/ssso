package com.atlassian.seraph.filter;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.ssso.ISimpleSSOPrincipal;

import com.atlassian.seraph.auth.Authenticator;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.config.SecurityConfig;

/**
 * This filter is compatible with the Seraph LoginFilter. It will deactivate if
 * the user successfully logs in with Seraph first. If it successfully
 * authenticates the user it will tell Seraph by setting LOGIN_SUCCESS status
 * and ALREADY_FILTERED attribute which will cause Seraph LoginFilter to
 * deactivate. Otherwise it keeps quiet so the standard Seraph LoginFilter can
 * activate. It must be used in conjunction with the SimpleSSOAuthenticator.
 */
public class SimpleSSOLoginFilter implements Filter {

    private static final Log log = LogFactory
            .getLog(SimpleSSOLoginFilter.class);

    private FilterConfig config = null;

    public static final String ALREADY_FILTERED = "loginfilter.already.filtered";

    public static final String LOGIN_SUCCESS = "success";

    public static final String LOGIN_FAILED = "failed";

    public static final String LOGIN_ERROR = "error";

    public static final String LOGIN_NOATTEMPT = null;

    public static final String OS_AUTHSTATUS_KEY = "os_authstatus";

    private SecurityConfig securityConfig = null;

    public void init(FilterConfig config) {
        // log.debug("LoginFilter.init");
        this.config = config;
    }

    public void destroy() {
        // log.debug("LoginFilter.destroy");
        config = null;
    }

    public void doFilter(ServletRequest req, ServletResponse res,
            FilterChain chain) throws IOException, ServletException {

        //log.debug("SimpleSSO.doFilter");

        if (!getSecurityConfig().getController().isSecurityEnabled()) {
            log
                    .debug("SimpleSSO.doFilter deactivated because security is disabled");
            chain.doFilter(req, res);
            return;
        }

        // Deactivate if another Seraph LoginFilter has attempted authentication
        // for this request
        Object authStatus = req.getAttribute(OS_AUTHSTATUS_KEY);
        if (authStatus != null) {
            String authStatus1 = (String) authStatus;
            if (!authStatus1.equals(LOGIN_NOATTEMPT)) {
                log
                        .debug("SimpleSSO.doFilter deactivated because a LoginFilter has already attempted authentication");
                chain.doFilter(req, res);
                return;
            }
        }

        if (req.getAttribute(ALREADY_FILTERED) != null) {
            log
                    .debug("SimpleSSO.doFilter deactivated because a LoginFilter has already processed this request");
            chain.doFilter(req, res);
            return;
        }

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        // Check for a SimpleSSO principal
        ISimpleSSOPrincipal user = getUserPrincipal(request);

        if (user != null) {

            // We don't want to repeatedly call getUser if we already know it
            // will
            // fail
            boolean principalLoginAlreadyFailed = false;
            if (request.getSession().getAttribute("LOG_IN_FAILURE") != null) {
                //log
                //        .debug("SimpleSSO.doFilter skipping login because login has already failed for: "
                //                + user.getUsername());
                chain.doFilter(req, res);
                return;
            }

            boolean loggedIn = false;
            try {
                // Save the principal to the session because we can't trust
                // getUserPrincipal() to work -- Seraph LoginFilter messes with
                // it.
                request.setAttribute(ISimpleSSOPrincipal.class
                        .getCanonicalName(), user);

                loggedIn = getAuthenticator().login(request, response,
                        user.getUsername(), "", false);
                if (loggedIn) {
                    log
                            .debug("Login was successful - setting attribute to \"Success\"");
                    // Announce to LoginFilter that it should deactivate
                    request.setAttribute(OS_AUTHSTATUS_KEY, LOGIN_SUCCESS);
                    req.setAttribute(ALREADY_FILTERED, Boolean.TRUE);
                } else {
                    log
                            .debug("Login was not successful - setting attribute to \"Failed\"");
                    // Keep quiet on failure
                    // request.setAttribute(OS_AUTHSTATUS_KEY, LOGIN_FAILED);

                    // We want to deactivate the filter for this session now.
                    request.getSession().setAttribute("LOG_IN_FAILURE", user);

                }
            } catch (AuthenticatorException e) {
                log
                        .debug("Login was not successful, and exception was thrown - setting attribute to \"Error\"");
                e.printStackTrace();
                log.warn("Exception was thrown whilst logging in: "
                        + e.getMessage(), e);
            }

        } else {
            log
                    .debug("userPrincipal was null or was not of type ISimpleSSOPrincipal");
        }

        chain.doFilter(req, res);

    }

    private ISimpleSSOPrincipal getUserPrincipal(HttpServletRequest request) {
        Principal p = request.getUserPrincipal();

        if (p != null && p instanceof ISimpleSSOPrincipal)
            return (ISimpleSSOPrincipal) p;
        else
            return null;

    }

    protected Authenticator getAuthenticator() {
        return getSecurityConfig().getAuthenticator();
    }

    protected SecurityConfig getSecurityConfig() {
        if (securityConfig == null) {
            securityConfig = (SecurityConfig) config.getServletContext()
                    .getAttribute(SecurityConfig.STORAGE_KEY);
        }
        return securityConfig;
    }
}
