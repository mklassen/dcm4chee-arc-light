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

import org.dcm4che3.net.*;
import org.dcm4che3.net.pdu.AAssociateRJ;
import org.dcm4che3.net.pdu.UserIdentityAC;
import org.dcm4che3.net.pdu.UserIdentityRQ;
import org.dcm4chee.arc.ArchiveUserIdentityNegotiator;
import org.dcm4chee.arc.ArchiveUserIdentityAC;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.TokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.OAuth2Constants;
import org.slf4j.LoggerFactory;
import org.keycloak.util.TokenUtil;

import javax.validation.constraints.NotNull;
import javax.ws.rs.NotAuthorizedException;
import java.io.IOException;
import java.security.*;

/**
 * @author Martyn Klassen <lmklassen@gmail.com>
 * @since June 2020
 */

public class KeycloakUserIdentityNegotiator extends ArchiveUserIdentityNegotiator {
    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(KeycloakUserIdentityNegotiator.class);

    protected UserIdentityAC negotiate(@NotNull Device device,
                                       @NotNull Association as,
                                       @NotNull UserIdentityRQ userIdentity) throws AAssociateRJ {

        switch (userIdentity.getType()) {
            case UserIdentityRQ.USERNAME_PASSCODE:
                return negotiate(userIdentity.getUsername(), new String(userIdentity.getPasscode()), device, as);
            case UserIdentityRQ.USERNAME:
                return negotiate(userIdentity.getUsername(), device, as);
            case 5: // DICOM Standard JWT not yet added to org.dcm4che3.net.pdu.UserIdentityRQ
                return negotiateToken(new String(userIdentity.getPrimaryField()), device, as);
            case UserIdentityRQ.KERBEROS:
            case UserIdentityRQ.SAML:
            default:
                break;
        }

        return null;
    }

    private ArchiveUserIdentityAC negotiateToken(String tokenString,
                                                 Device device,
                                                 Association as) {

        AccessToken token = null;
        for (KeycloakClient keycloakClient : this.getKeycloakClients(device, as)) {
            try {
                token = TokenVerifier.create(tokenString, AccessToken.class)
                        .withDefaultChecks()
                        .audience("account")
                        .issuedFor(keycloakClient.getKeycloakClientID())
                        .tokenType(TokenUtil.TOKEN_TYPE_BEARER)
                        .verify()
                        .getToken();
            } catch (VerificationException e) {
                continue;
            }

            if (token != null) {
                return populateUser(token, keycloakClient.getKeycloakClientID(), new ArchiveUserIdentityAC(new byte[0]));
            }
        }

        LOG.debug("Token verification failed");
        return null;
    }

    private ArchiveUserIdentityAC negotiate(String username,
                                            Device device,
                                            Association as) throws AAssociateRJ {

        // Get the credentials for the username without password
        // Use the Keycloak client credentials instead
        // Using this without AE Title restrictions allows authentication as any user without corresponding passcode
        for (KeycloakClient keycloakClient : this.getKeycloakClients(device, as)) {

            ArchiveUserIdentityAC userIdentityAC = getUserIdentity(
                    keycloakClient.getKeycloakServerURL(),
                    keycloakClient.getKeycloakRealm(),
                    keycloakClient.getKeycloakClientID(),
                    keycloakClient.getKeycloakClientSecret(),
                    OAuth2Constants.CLIENT_CREDENTIALS,
                    username,
                    null,
                    keycloakClient.isTLSAllowAnyHostname(),
                    keycloakClient.isTLSDisableTrustManager(),
                    device);

            if (userIdentityAC != null)
                return userIdentityAC;
        }

        LOG.debug("Unable to authenticate " + username + " without passcode.");
        return null;
    }

    private ArchiveUserIdentityAC negotiate(String username,
                                            String passcode,
                                            Device device,
                                            Association as) throws AAssociateRJ {

        for (KeycloakClient keycloakClient : this.getKeycloakClients(device, as)) {
            ArchiveUserIdentityAC userIdentityAC = getUserIdentity(
                    keycloakClient.getKeycloakServerURL(),
                    keycloakClient.getKeycloakRealm(),
                    keycloakClient.getKeycloakClientID(),
                    keycloakClient.getKeycloakClientSecret(),
                    OAuth2Constants.PASSWORD,
                    username,
                    passcode,
                    keycloakClient.isTLSAllowAnyHostname(),
                    keycloakClient.isTLSDisableTrustManager(),
                    device);

            if (userIdentityAC != null)
                return userIdentityAC;
        }

        LOG.debug("Unable to authenticate " + username + " with passcode.");
        return null;
    }

    private static ResteasyClientBuilder createResteasyClientBuilder(
            String url,
            Device device,
            boolean allowAnyHostname,
            boolean disableTrustManager) throws AAssociateRJ {

        ResteasyClientBuilder builder = new ResteasyClientBuilder();
        if (url.toLowerCase().startsWith("https")) {
            try {
                builder.sslContext(device.sslContext())
                        .hostnameVerification(allowAnyHostname
                                ? ResteasyClientBuilder.HostnameVerificationPolicy.ANY
                                : ResteasyClientBuilder.HostnameVerificationPolicy.WILDCARD);
            } catch (IOException | GeneralSecurityException e) {
                LOG.error("SSL Context: " + e.getMessage());
                throw new AAssociateRJ(AAssociateRJ.RESULT_REJECTED_PERMANENT,
                        AAssociateRJ.SOURCE_SERVICE_USER,
                        AAssociateRJ.REASON_NO_REASON_GIVEN);
            }

            if (disableTrustManager)
                builder.disableTrustManager();
        }

        // org.jboss.resteasy.plugins.providers.jsonb.JsonBindingProvider is a builtin, but corrupt as
        // AccessTokenResponse has an empty token.
        // org.jboss.resteasy.plugins.providers.jackson.ResteasyJackson2Provider is also a builtin, so it
        // cannot be registered again with a higher priority and JsonBindingProvider beats
        // ResteasyJackson2Provider by default.
        // org.keycloak.admin.client.JacksonProvider extends ResteasyJackson2Provider and should be able to be
        // registered with higher priority than JsonBindingProvider, but there is some linkage issue when
        // loading JacksonProvider being unable to find
        // org.jboss.resteasy.plugins.providers.jackson.ResteasyJackson2Provider even though
        // ResteasyJackson2Provider itself can be registered without issue.
        // The work around is to create a class that extends ResteasyJackson2Provider and can be register with a higher
        // priority than JsonBindingProvider
        builder.register(KeycloakProvider.class, 1000);

        return builder;
    }

    private static ArchiveUserIdentityAC getUserIdentity(
            String url,
            String realm,
            String clientId,
            String clientSecret,
            String grantType,
            String username,
            String passcode,
            boolean allowAnyHostname,
            boolean disableTrustManger,
            Device device) throws AAssociateRJ {

        LOG.debug("Authenticating using " + url + "/realms/" +
                realm + " with client " +
                clientId + " for user " + username);

        Keycloak server;
        try {
            server = KeycloakBuilder.builder()
                    .serverUrl(url)
                    .realm(realm)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .username(username)
                    .password(passcode)
                    .grantType(grantType)
                    .resteasyClient(createResteasyClientBuilder(
                            url,
                            device,
                            allowAnyHostname,
                            disableTrustManger).build())
                    .build();
        }
        catch (IllegalStateException e)
        {
            LOG.debug("Failed to build keycloak server");
            return null;
        }

        AccessTokenResponse response;
        try {
            response = server.tokenManager().getAccessToken();
        } catch (NotAuthorizedException e) {
            LOG.debug("Not Authorized: " + e.getMessage());
            return null;
        }

        // User has been authenticated as a valid user
        ArchiveUserIdentityAC userIdentityAC = new ArchiveUserIdentityAC(new byte[0]);

        if (response == null) {
            LOG.debug("null AccessTokenResponse");
            return userIdentityAC;
        }

        // Extract AccessToken from response token string
        // Verification is not necessary because we just got the token from keycloak server
        AccessToken token;
        try {
            token = TokenVerifier.create(response.getToken(), AccessToken.class).getToken();
        } catch (VerificationException e) {
            LOG.info("Token verification error: " + e.getMessage());
            return userIdentityAC;
        }

        return populateUser(token, clientId, userIdentityAC);
    }

    private static ArchiveUserIdentityAC populateUser(AccessToken token,
                                                      String clientId,
                                                      ArchiveUserIdentityAC userIdentityAC) {
        // Add the roles to the userIdentityAC
        AccessToken.Access access = token.getRealmAccess();
        if (access != null)
            userIdentityAC.addRealmRoles(access.getRoles());

        access = token.getResourceAccess(clientId);
        if (access != null)
            userIdentityAC.addClientRoles(access.getRoles());

        return userIdentityAC;
    }
}
