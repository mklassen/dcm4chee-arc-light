/*
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 *  The contents of this file are subject to the Mozilla Public License Version
 *  1.1 (the "License"); you may not use this file except in compliance with
 *  the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS" basis,
 *  WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 *  for the specific language governing rights and limitations under the
 *  License.
 *
 *  The Original Code is part of dcm4che, an implementation of DICOM(TM) in
 *  Java(TM), hosted at https://github.com/dcm4che.
 *
 *  The Initial Developer of the Original Code is
 *  J4Care.
 *  Portions created by the Initial Developer are Copyright (C) 2015-2017
 *  the Initial Developer. All Rights Reserved.
 *
 *  Contributor(s):
 *  See @authors listed below
 *
 *  Alternatively, the contents of this file may be used under the terms of
 *  either the GNU General Public License Version 2 or later (the "GPL"), or
 *  the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 *  in which case the provisions of the GPL or the LGPL are applicable instead
 *  of those above. If you wish to allow use of your version of this file only
 *  under the terms of either the GPL or the LGPL, and not to allow others to
 *  use your version of this file under the terms of the MPL, indicate your
 *  decision by deleting the provisions above and replace them with the notice
 *  and other provisions required by the GPL or the LGPL. If you do not delete
 *  the provisions above, a recipient may use your version of this file under
 *  the terms of any one of the MPL, the GPL or the LGPL.
 *
 */

package org.dcm4chee.arc.keycloak;

import org.keycloak.representations.AccessToken;

import java.util.Collections;
import java.util.Set;

/**
 * @author Martyn Klassen <lmklassen@gmail.com>
 * @since July 2020
 */

public class ClientRoles {

    public static Set<String> get(HttpServletRequestInfo request) {

        if (request != null && request.requestKSC != null) {
            return get(request.requestKSC.getToken(), null);
        }

        return null;
    }

    public static Set<String> get(AccessToken token, String client_id) {
        if (token == null)
            return Collections.emptySet();

        String clientid = client_id == null
                ? (token.getOtherClaims().get("azp") == null
                ? System.getProperty("ui-client-id","dcm4chee-arc-ui")
                : token.getOtherClaims().get("azp").toString())
                : client_id;

        if (clientid == null)
            return Collections.emptySet();

        AccessToken.Access access = token.getResourceAccess(clientid);
        if (access == null)
            return Collections.emptySet();

        return access.getRoles();
    }
}
