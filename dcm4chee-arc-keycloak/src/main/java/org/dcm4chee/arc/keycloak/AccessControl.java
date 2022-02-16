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

import java.net.URI;
import java.net.http.HttpClient;
import org.dcm4che3.net.Association;
import org.dcm4che3.net.KeycloakClient;
import org.dcm4che3.net.pdu.AAssociateAC;
import org.dcm4che3.net.pdu.UserIdentityAC;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;

/**
 * @author Martyn Klassen <lmklassen@gmail.com>
 * @since July 2020
 */

public class AccessControl {
    public static Set<String> getRoles(AccessToken accessToken) {
        Set<String> roles = new HashSet<>();
        if (accessToken == null)
            return roles;

        AccessToken.Access access = accessToken.getRealmAccess();
        if (access != null)
            roles.addAll(access.getRoles());

        access = accessToken.getResourceAccess(accessToken.getIssuedFor());
        if (access != null)
            roles.addAll(access.getRoles());

        return roles;
    }

    public static Set<String> getTokenAccessControlIDs(String tokenString, KeycloakClient keycloakClient){
        TokenVerifier<AccessToken> tokenVerifier = TokenVerifier.create(tokenString, AccessToken.class);

        try {
            AccessToken token = tokenVerifier.getToken();
            if (token == null)
                return null;
            UserInfoWithAccessControl userInfo = doUserInfoRequest(
                    tokenString,
                    keycloakClient.getKeycloakServerURL() + "realms/" + keycloakClient.getKeycloakRealm()
            );

            if (userInfo != null) {
                String[] accessControl = userInfo.getAccessControl();
                if (accessControl != null) {
                    return new HashSet<>(Arrays.asList(accessControl));
                }
            }
            return Collections.emptySet();
        }
        catch(VerificationException e){
            return null;
        }
    }

    protected static UserInfoWithAccessControl doUserInfoRequest(String accessTokenString, String keycloakRealmUrl) {
        try {
            // obtain userinfo url from openid-configuration endpoint
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest oidcRequest = HttpRequest.newBuilder(
                            URI.create(keycloakRealmUrl + "/.well-known/openid-configuration"))
                    .build();
            HttpResponse<String> oidcResponse = client.send(oidcRequest, HttpResponse.BodyHandlers.ofString());
            OIDCConfigurationRepresentation oidcConfig = JsonSerialization.readValue(oidcResponse.body(), OIDCConfigurationRepresentation.class);

            // obtain userinfo (with access_control entry)
            HttpRequest userinfoRequest = HttpRequest.newBuilder(
                            URI.create(oidcConfig.getUserinfoEndpoint()))
                    .header("Authorization", "Bearer " + accessTokenString)

                    .build();
            HttpResponse<String> userinfoResponse = client.send(userinfoRequest, HttpResponse.BodyHandlers.ofString());

            return JsonSerialization.readValue(userinfoResponse.body(), UserInfoWithAccessControl.class);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        } catch (InterruptedException e) {
            return null;
        }
    }

    public static boolean isUserInRole(AccessToken token, String role){
        if (role == null)
            return true;

        if (token == null)
            return false;

        AccessToken.Access access = token.getRealmAccess();
        if (token != null && access.isUserInRole(role))
            return true;

        access = token.getResourceAccess(token.getIssuedFor());
        return access != null && access.isUserInRole(role);
    }

    public static String[] getAccessControlIDs(String[] arcAEAccessControlIDs, HttpServletRequestInfo httpServletRequestInfo, Association requestAssociation, KeycloakClient keycloakClient) {

        Set<String> accessControlIDSet = new HashSet<>();
        Set<String> arcAEAccessControlIDSet = new HashSet<>(Arrays.asList(arcAEAccessControlIDs));

        String datacareRole = System.getProperty("datacare-user-role", "datacare");
        AccessToken accessToken = null;

        // Use token found in the HTTP request, if any
        if (httpServletRequestInfo != null && httpServletRequestInfo.requestKSC != null) {
            Set<String> tokenAccessControlIDs = getTokenAccessControlIDs(
                    httpServletRequestInfo.requestKSC.getTokenString(),
                    keycloakClient
            );
            if (tokenAccessControlIDs != null)
                accessControlIDSet.addAll(tokenAccessControlIDs);
            accessToken = httpServletRequestInfo.requestKSC.getToken();
        }

        // Assign accessControlIDs found in the DICOM association token, if any
        if (null != requestAssociation) {
            AAssociateAC ac = requestAssociation.getAAssociateAC();
            if (null != ac) {
                UserIdentityAC userIdentityAC = ac.getUserIdentityAC();

                if (userIdentityAC instanceof ArchiveUserIdentityAC) {
                    accessControlIDSet.addAll(
                            ((ArchiveUserIdentityAC) userIdentityAC).getAccessControlIDs()
                    );
                    accessToken = ((ArchiveUserIdentityAC) userIdentityAC).getAccessToken();
                }
            }
        }

        // override Role-Based Access Control
        // - if user has datacareRole
        // - if both http request info and DICOM request association object are null
        //  This happens in e.g. Storage Commitment SCP, which does not store the association in
        //  the retrieve service/context used to access the data
        boolean overrideRoleBasedAccessControl = (( requestAssociation == null && httpServletRequestInfo == null ) ||
                AccessControl.isUserInRole(
                accessToken,
                datacareRole
        ));

        if (overrideRoleBasedAccessControl){
            // empty set of token-derived accessControlIDs, which disables filtering on them
            accessControlIDSet.clear();
            accessControlIDSet.addAll(arcAEAccessControlIDSet);
        } else {
            if (!arcAEAccessControlIDSet.isEmpty())
                accessControlIDSet.retainAll(arcAEAccessControlIDSet);

            // Having no accessControlIDs would allow user to query/retrieve everything
            // Add '*' accessControlID to ensure that at least one is present
            accessControlIDSet.add("*");
        }

        return accessControlIDSet.toArray(new String[0]);
    }
}
