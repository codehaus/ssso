package org.codehaus.ssso;

import java.security.Principal;

/**
 * An extended principal supporting the SimpleSSO authentication system.
 * 
 * @author drand
 * 
 */
public interface ISimpleSSOPrincipal extends Principal {

    public String getEmail();

    public String getUsername();

}
