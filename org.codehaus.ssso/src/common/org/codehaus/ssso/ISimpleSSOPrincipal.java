package org.codehaus.ssso;

import java.security.Principal;

/**
 * TODO Rename this to ISimpleSSOUser
 * 
 * @author drand
 * 
 */
public interface ISimpleSSOPrincipal extends Principal {
    
    public String getEmail();

    public String getUsername();

}
