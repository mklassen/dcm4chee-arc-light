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
import org.dcm4che3.net.UserIdentityNegotiator;
import org.dcm4che3.net.pdu.AAssociateRJ;
import org.dcm4che3.net.pdu.UserIdentityAC;
import org.dcm4che3.net.pdu.UserIdentityRQ;
import org.dcm4chee.arc.conf.ArchiveDeviceExtension;
import org.dcm4chee.arc.conf.KeycloakServer;
import org.dcm4chee.arc.conf.UserIdentityAccessControlAC;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.authorization.client.AuthorizationDeniedException;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.representations.idm.authorization.Permission;

import javax.servlet.http.HttpServletRequest;
import java.util.*;


public class KeycloakUserIdNegotiator implements UserIdentityNegotiator {

    public static Set<String> generateAccessControlIDs(HttpServletRequest request)
    {
        List<Permission> permissions = new ArrayList<>();

        if (null != request) {
            KeycloakSecurityContext ksc = (KeycloakSecurityContext) request.getAttribute("org.keycloak.KeycloakSecurityContext");

            if (null != ksc) {
                permissions.addAll(ksc.getAuthorizationContext().getPermissions());
            }
        }

        return generateAccessControlIDs(permissions);
    }

    private static Set<String> generateAccessControlIDs(List<Permission> permissionList)
    {
        Set<String> accessControlIDs = new HashSet<>();

        for (Permission permission : permissionList) {
            if (permission.getScopes().contains("accessControlID")) {
                accessControlIDs.add(permission.getResourceName());
            }
        }

        return accessControlIDs;
    }

    public UserIdentityAC negotiate(Association as, UserIdentityRQ userIdentity) throws AAssociateRJ {
        // Get the ArchiveDeviceExtension to obtain the configured Keycloak servers
        ArchiveDeviceExtension arcDev = as.getApplicationEntity().getDevice().getDeviceExtension(ArchiveDeviceExtension.class);

        // Make sure the user identity request is not null and the ArchiveDeviceExtension is valid
        // Handle username and password authentication requests only
        if (!Objects.isNull(userIdentity) && !Objects.isNull(arcDev) && userIdentity.getType() == 2) {

            // Loop through all configured Keycloak servers until successfully authenticated
            for (KeycloakServer keycloakServer : arcDev.getKeycloakServers())
            {
                // Create a configuration for the Keycloak server
                Map<String, Object> credentials = new HashMap<>();
                credentials.put("secret", keycloakServer.getClientSecret());
                Configuration configuration = new Configuration(
                        keycloakServer.getServerURL(),
                        keycloakServer.getRealm(),
                        keycloakServer.getClientID(),
                        credentials,
                        null
                        );

                // Use AuthzClient to authenticate
                AuthzClient authzClient = AuthzClient.create(configuration);
                AuthorizationResponse response;
                try {
                    response = authzClient.authorization(userIdentity.getUsername(),
                            new String(userIdentity.getPasscode())).authorize();
                }
                catch (AuthorizationDeniedException e) {
                    // Authorization failure, try next server
                    continue;
                }
                return new UserIdentityAccessControlAC(generateAccessControlIDs(
                        authzClient.protection().introspectRequestingPartyToken(response.getToken()).getPermissions()),
                        new byte[0]);
            }
        }

        // In all other cases we reject the association
        throw new AAssociateRJ(AAssociateRJ.RESULT_REJECTED_PERMANENT,
                AAssociateRJ.SOURCE_SERVICE_USER,
                AAssociateRJ.REASON_NO_REASON_GIVEN);
    }

}
