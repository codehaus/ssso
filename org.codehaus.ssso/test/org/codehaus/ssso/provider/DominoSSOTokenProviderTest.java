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

import java.io.IOException;
import java.net.URL;
import java.util.Properties;

import junit.framework.TestCase;

import org.codehaus.ssso.token.ISimpleSSOToken;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class DominoSSOTokenProviderTest extends TestCase {

    private ClassPathXmlApplicationContext ctx;

    // GenericToken tests
    final String beanName;

    final String testUsername;

    final String testPassword;

    public DominoSSOTokenProviderTest() throws IOException {
        
        Properties p = new Properties();
        p.load(ClassLoader.getSystemResourceAsStream("tests.properties"));
        beanName = p.getProperty("beanName");
        testUsername = p.getProperty("testUsername");
        testPassword = p.getProperty("testPassword");
        
        String[] paths = { "sssoContext.xml" };
        ctx = new ClassPathXmlApplicationContext(paths);
    }

    public void testAttemptAuthentication() {

        ISSOTokenProvider tokenProvider = (ISSOTokenProvider) ctx
                .getBean(beanName);

        // Valid credentials
        ISimpleSSOToken testToken = tokenProvider.authenticate(testUsername, testPassword);
        
        // Invalid credentials
        try {
            tokenProvider.authenticate(testUsername, "gibberish");
            fail("Authentication should have failed");
        } catch (ISSOTokenProvider.AuthenticationException e) {
            // Expected
        }

    }
    
    public void testAlreadyAuthenticated() {

        ISSOTokenProvider tokenProvider = (ISSOTokenProvider) ctx
                .getBean(beanName);

        ISimpleSSOToken testToken = tokenProvider.authenticate(testUsername, testPassword);
        String testTokenString = testToken.toString();
        
        // Valid credentials
        tokenProvider.authenticate(testTokenString);

        try {
            tokenProvider.authenticate(testTokenString + "g");
            fail("Authentication should have failed");
        } catch (ISSOTokenProvider.AuthenticationException e) {
            // Expected
        }

    }


}
