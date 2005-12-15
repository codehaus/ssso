/*
 * Copyright 1999,2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.codehaus.ssso.provider;

import java.security.Principal;
import java.util.Arrays;
import java.util.List;

/**
 * Generic implementation of <strong>java.security.Principal</strong> that is
 * available for use by <code>Realm</code> implementations.
 * 
 * @author Craig R. McClanahan
 * @version $Revision: 1.4 $ $Date: 2004/02/27 14:58:45 $
 */

public class GenericPrincipal implements Principal {

    // ----------------------------------------------------------- Constructors

    /**
     * Construct a new Principal, associated with the specified Realm, for the
     * specified username and password.
     * 
     * @param realm
     *            The Realm that owns this Principal
     * @param name
     *            The username of the user represented by this Principal
     * @param password
     *            Credentials used to authenticate this user
     */
    public GenericPrincipal(String name, String password) {

        this(name, password, null);

    }

    public GenericPrincipal(String name, String password, List roles) {

        super();
        this.name = name;
        this.password = password;
        if (roles != null) {
            this.roles = new String[roles.size()];
            this.roles = (String[]) roles.toArray(this.roles);
            if (this.roles.length > 0)
                Arrays.sort(this.roles);
        }
    }

    // ------------------------------------------------------------- Properties

    /**
     * The username of the user represented by this Principal.
     */
    protected String name = null;

    public String getName() {
        return (this.name);
    }

    /**
     * The authentication credentials for the user represented by this
     * Principal.
     */
    protected String password = null;

    public String getPassword() {
        return (this.password);
    }

    /**
     * The set of roles associated with this user.
     */
    protected String roles[] = new String[0];

    public String[] getRoles() {
        return (this.roles);
    }

    // --------------------------------------------------------- Public Methods

    /**
     * Does the user represented by this Principal possess the specified role?
     * 
     * @param role
     *            Role to be tested
     */
    public boolean hasRole(String role) {

        if ("*".equals(role)) // Special 2.4 role meaning everyone
            return true;
        if (role == null)
            return (false);
        return (Arrays.binarySearch(roles, role) >= 0);

    }

    /**
     * Return a String representation of this object, which exposes only
     * information that should be public.
     */
    public String toString() {

        StringBuffer sb = new StringBuffer("GenericPrincipal[");
        sb.append(this.name);
        sb.append("(");
        for (int i = 0; i < roles.length; i++) {
            sb.append(roles[i]).append(",");
        }
        sb.append(")]");
        return (sb.toString());

    }

}
