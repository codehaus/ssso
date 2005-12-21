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
package org.codehaus.ssso.provider;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.ssso.token.DominoLtpaToken;
import org.codehaus.ssso.token.ISimpleSSOToken;

/**
 * This IDominoLoginModule makes an HTTP connection to a form to get an
 * LtpaToken from the provided credentials
 * 
 * @author drand
 * 
 */
public class DominoSSOTokenProvider implements ISSOTokenProvider {
    
    private final static Log log = LogFactory.getLog(DominoSSOTokenProvider.class);

    private static final String ENCODING = "UTF-8";

    // **********************
    // Bean fields
    // **********************

    /**
     * The location of a Domino login form that can take a username and password
     * as form parameters and return the LtpaToken in the cookie.
     */
    protected URL loginUrl;

    /**
     * Domino secret used for token validation
     */
    protected String dominoSecret;

    /**
     * Domino charset used for token character values
     */
    protected String dominoCharset;

    // **********************
    // End of bean fields
    // **********************

    /**
     * 
     * @param loginUrl
     *            Hyperlink to authentication action. eg.
     *            http://128.1.32.165/names.nsf?Login
     * @param dominoSecret
     *            Needed to validate the ltpaToken
     */
    public DominoSSOTokenProvider(URL loginUrl, String dominoSecret,
            String dominoCharset) {

        if (loginUrl == null || dominoSecret == null || dominoCharset == null)
            throw new IllegalArgumentException();

        this.loginUrl = loginUrl;
        this.dominoSecret = dominoSecret;
        this.dominoCharset = dominoCharset;
    }

    /**
     * @returns The session cookie if the user is successfully authenticated;
     *          else null.
     */
    public ISimpleSSOToken authenticate(String user, String password) {

        HttpURLConnection connection;
        try {
            connection = (HttpURLConnection) loginUrl.openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
        } catch (IOException e) {
            throw new AuthenticationException(e);
        } catch (Exception e) {
            throw new AuthenticationException(e);
        }

        StringBuffer params = new StringBuffer();
        params.append("RedirectTo=");
        params.append("&");
        params.append("Password=");
        params.append(encode(password));
        params.append("&");
        params.append("Username=");
        params.append(encode(user));
        params.append("&");
        params.append("ModDate=");

        BufferedWriter bw;
        int response;
        try {
            bw = new BufferedWriter(new OutputStreamWriter(connection
                    .getOutputStream()));
            bw.write(params.toString());
            bw.flush();
            bw.close();
            response = connection.getResponseCode();
        } catch (IOException e) {
            throw new AuthenticationException(e);
        }

        if (response != HttpURLConnection.HTTP_MOVED_TEMP)
            throw new AuthenticationException("Invalid username or password");

        String tokenCookie = connection.getHeaderField("Set-Cookie");

        Pattern p = Pattern.compile("LtpaToken=(.*); domain=.*; path=/");
        Matcher m = p.matcher(tokenCookie);
        String tokenString = null;
        if (m.matches() == true) {
            tokenString = m.group(1);
        }

        return new DominoLtpaToken(tokenString, dominoSecret, dominoCharset);
    }

    private String encode(String password) {
        try {
            return URLEncoder.encode(password, ENCODING);
        } catch (UnsupportedEncodingException e) {
            throw new AuthenticationException(e);
        }
    }

    public URL getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(URL loginUrl) {
        this.loginUrl = loginUrl;
    }

    public ISimpleSSOToken authenticate(String tokenString) {

        try{
            DominoLtpaToken token = new DominoLtpaToken(tokenString, dominoSecret, dominoCharset);
            return token;
        }catch(IllegalArgumentException e){
            throw new AuthenticationException(e);
        }
    }

}