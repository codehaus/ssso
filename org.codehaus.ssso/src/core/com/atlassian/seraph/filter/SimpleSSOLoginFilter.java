package com.atlassian.seraph.filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Category;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Iterator;

import com.atlassian.seraph.config.SecurityConfig;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.Authenticator;
import com.atlassian.seraph.auth.SimpleSSOAuthenticator;
import com.atlassian.seraph.interceptor.LoginInterceptor;

/**
 * Logs the user in based on Container security
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

        if (req.getAttribute(ALREADY_FILTERED) != null
                || !getSecurityConfig().getController().isSecurityEnabled()) {
            chain.doFilter(req, res);
            return;
        } else {
            req.setAttribute(ALREADY_FILTERED, Boolean.TRUE);
        }

        req.setAttribute(OS_AUTHSTATUS_KEY, LOGIN_NOATTEMPT);

        HttpServletRequest request = (HttpServletRequest) req;

        // check for parameters

        Principal user = request.getUserPrincipal();

        if (user != null) {
            log
                    .debug("Login was successful - setting attribute to \"Success\"");
            request.setAttribute(OS_AUTHSTATUS_KEY, LOGIN_SUCCESS);
        } else {
            log
                    .debug("Login was not successful - setting attribute to \"Failed\"");
            request.setAttribute(OS_AUTHSTATUS_KEY, LOGIN_FAILED);
        }

        chain.doFilter(req, res);
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
