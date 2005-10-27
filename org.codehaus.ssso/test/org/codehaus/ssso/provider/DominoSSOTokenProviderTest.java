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

import java.net.URL;

import junit.framework.TestCase;

import org.springframework.context.support.ClassPathXmlApplicationContext;

public class DominoSSOTokenProviderTest extends TestCase {

    private ClassPathXmlApplicationContext ctx;

    // GenericToken tests
    final String beanName = "allowAllSSOTokenProvider";

    final String testusername = "Damon Rand";

    final String testpassword = "secret";

    final String testtoken = "Damon Rand:secret";

    public DominoSSOTokenProviderTest() {
        String[] paths = { "ssoContext.xml" };
        ctx = new ClassPathXmlApplicationContext(paths);
    }

    public void testAlreadyAuthenticated() {

        ISSOTokenProvider tokenProvider = (ISSOTokenProvider) ctx
                .getBean(beanName);

        // Valid credentials
        tokenProvider.authenticate(testtoken);

        try {
            tokenProvider.authenticate(testtoken + "g");
            fail("Authentication should have failed");
        } catch (ISSOTokenProvider.AuthenticationException e) {
            // Expected
        }

    }

    public void testAttemptAuthentication() {

        ISSOTokenProvider tokenProvider = (ISSOTokenProvider) ctx
                .getBean(beanName);

        // Valid credentials
        tokenProvider.authenticate(testusername, testpassword);

        // Invalid credentials
        try {
            tokenProvider.authenticate(testusername, "gibberish");
            fail("Authentication should have failed");
        } catch (ISSOTokenProvider.AuthenticationException e) {
            // Expected
        }

    }

}
