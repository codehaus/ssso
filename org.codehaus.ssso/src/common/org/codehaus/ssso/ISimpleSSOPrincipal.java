package org.codehaus.ssso;


import java.security.Principal;

public interface ISimpleSSOPrincipal extends Principal {

    public String getEmail();

    public String getUsername();

}
