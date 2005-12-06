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
package org.codehaus.ssso.token;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.text.DateFormat;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * Test the DominoLtpaToken class
 * 
 * @author drand
 * 
 */
public class DominoLtpaTokenTest extends TestCase {

    public static Log log = LogFactory.getLog(DominoLtpaTokenTest.class);

    String SECRET;

    String LTPA_TOKEN;

    final String CHARSET = "Cp850";

    private ClassPathXmlApplicationContext ctx;

    public DominoLtpaTokenTest() throws IOException {
        Properties p = new Properties();
        p.load(ClassLoader.getSystemResourceAsStream("tests.properties"));
        SECRET = p.getProperty("sampleDominoSecret");
        LTPA_TOKEN = p.getProperty("sampleDominoToken");
    }

    public void testTokenConstructor() {
        
        // Test the class
        ISimpleSSOToken token = new DominoLtpaToken(LTPA_TOKEN, SECRET, CHARSET);

        DateFormat dateFormat = DateFormat.getInstance();
        log.info("-" + dateFormat.format(token.getCreationDate()) + "-");
        log.info("-" + dateFormat.format(token.getExpiresDate()) + "-");
        log.info("-" + token.getDistinguishedName() + "-");

        assertTrue(token.isValid());

        try{
            token = new DominoLtpaToken("a", SECRET, CHARSET);
            fail("Expected IllegalArgumentException");
        }catch(IllegalArgumentException e){
            
        }

    }

    public void testValidity() {
        ISimpleSSOToken token = new DominoLtpaToken(LTPA_TOKEN, SECRET, CHARSET);
        assertTrue(token.isValid());
    }

    public void testExpired() {
        ISimpleSSOToken token = new DominoLtpaToken(LTPA_TOKEN, SECRET, CHARSET);
        assertTrue(token.isExpired());

    }

}
