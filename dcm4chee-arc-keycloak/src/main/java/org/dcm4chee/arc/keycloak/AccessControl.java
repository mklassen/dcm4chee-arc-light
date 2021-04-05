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

import org.dcm4che3.net.Association;
import org.dcm4che3.net.pdu.AAssociateAC;
import org.dcm4che3.net.pdu.UserIdentityAC;
import org.keycloak.representations.AccessToken;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Martyn Klassen <lmklassen@gmail.com>
 * @since July 2020
 */

public class AccessControl {
    public static Set<String> parseToken(AccessToken token, String client_id) {
        if (token == null)
            return Collections.emptySet();

        String resource_id = token.getIssuedFor();
        if (resource_id == null) {
            if (client_id != null)
                resource_id = client_id;
            else
                resource_id = System.getProperty("ui-client-id", "dcm4chee-arc-ui");
        }

        AccessToken.Access access = token.getResourceAccess(resource_id);
        if (access == null)
            return Collections.emptySet();

        return access.getRoles();
    }

    public static String[] getAccessControlIDs(String[] arcAEAccessControlIDs, HttpServletRequestInfo httpServletRequestInfo, Association requestAssociation) {

        Set<String> accessControlIDSet = new HashSet<>();

        // Assign roles found in the HTTP request, if any
        if (httpServletRequestInfo != null && httpServletRequestInfo.requestKSC != null) {
            accessControlIDSet.addAll(parseToken(httpServletRequestInfo.requestKSC.getToken(), null));
        }

        // Assign roles found in the DICOM association, if any
        if (null != requestAssociation) {
            AAssociateAC ac = requestAssociation.getAAssociateAC();
            if (null != ac) {
                UserIdentityAC userIdentityAC = ac.getUserIdentityAC();

                if (userIdentityAC instanceof ArchiveUserIdentityAC) {
                    accessControlIDSet.addAll(
                            ((ArchiveUserIdentityAC) userIdentityAC).getClientRoles()
                    );
                }
            }
        }

        // if datacare role in accessControlIDSet
        if(accessControlIDSet.contains(System.getProperty("datacare-user-role", "datacare"))){
            // if there are any AE access control IDs, they take precedence. Assign them and return.
            if(arcAEAccessControlIDs.length > 0){
                accessControlIDSet.clear();
                accessControlIDSet.addAll(Arrays.asList(arcAEAccessControlIDs));
            }
            else{
                // Return empty array.
                // No accessControlID filters will be added to queries and user will see all datasets
                return new String[0];
            }
        }
        else {

            // Filter roles to only include those that are defined for AE (if any are defined for AE)
            if (arcAEAccessControlIDs.length > 0) {
                accessControlIDSet.retainAll(Arrays.asList(arcAEAccessControlIDs));
            }

            if (accessControlIDSet.isEmpty()) {
                // The user has no client roles, so only '*' studies may be accessed
                // To ensure that at least one accessControlID is present so they do not see everything
                accessControlIDSet.add("*");
            }
        }
        return accessControlIDSet.toArray(new String[0]);
    }
}
