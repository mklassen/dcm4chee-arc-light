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
package org.dcm4chee.arc;

import org.dcm4che3.net.*;
import org.dcm4che3.net.pdu.AAssociateRJ;
import org.dcm4che3.net.pdu.UserIdentityAC;
import org.dcm4che3.net.pdu.UserIdentityRQ;
import org.dcm4chee.arc.conf.ArchiveAEExtension;
import org.dcm4chee.arc.conf.ArchiveDeviceExtension;
import org.slf4j.LoggerFactory;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.Collection;

import static org.dcm4che3.net.WebApplication.ServiceClass.DCM4CHEE_ARC_AET;

/**
 * @author Martyn Klassen <lmklassen@gmail.com>
 * @since June 2020
 */

public abstract class ArchiveUserIdentityNegotiator implements UserIdentityNegotiator {
    private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(ArchiveUserIdentityNegotiator.class);

    protected ArchiveUserIdentityAC negotiateUsernamePasscode(@NotNull String username,
                                                              @NotNull String passcode,
                                                              @NotNull Device device,
                                                              @NotNull Association as) throws AAssociateRJ {
        return null;
    }

    protected ArchiveUserIdentityAC negotiateUsername(@NotNull String username,
                                                      @NotNull Device device,
                                                      @NotNull Association as) throws AAssociateRJ {
        return null;
    }

    protected ArchiveUserIdentityAC negotiateJWT(@NotNull String token,
                                                 @NotNull Device device,
                                                 @NotNull Association as) throws AAssociateRJ {
        return null;
    }

    protected ArchiveUserIdentityAC negotiateSAML(@NotNull String token,
                                                  @NotNull Device device,
                                                  @NotNull Association as) throws AAssociateRJ {
        return null;
    }

    protected ArchiveUserIdentityAC negotiateKerberos(@NotNull String ticket,
                                                      @NotNull Device device,
                                                      @NotNull Association as) throws AAssociateRJ {
        return null;
    }

    public UserIdentityAC negotiate(Association as, UserIdentityRQ userIdentity) throws AAssociateRJ {

        if (as == null) {
            LOG.error("Unable to negotiate user without Association");
            throw new AAssociateRJ(AAssociateRJ.RESULT_REJECTED_PERMANENT,
                    AAssociateRJ.SOURCE_SERVICE_USER,
                    AAssociateRJ.REASON_NO_REASON_GIVEN);
        }

        // Default is to reject failed authentications to prevent leaking on inability to obtain ArchiveAEExtension
        boolean rejectIfNoUserIdentity = true;

        Device device = as.getDevice();
        String[] userTypes = {};
        if (device != null) {
            // Get the ArchiveDevice Extension settings, in case no ArchiveAEExtension exists
            ArchiveDeviceExtension arcDev = device.getDeviceExtension(ArchiveDeviceExtension.class);
            if (arcDev != null) {
                rejectIfNoUserIdentity = arcDev.isRejectIfNoUserIdentity();
                userTypes = arcDev.getUserIdentityTypes();
            }

            // Override with the ArchiveAEExtension settings
            ApplicationEntity ae = device.getApplicationEntity(as.getLocalAET());
            if (ae != null) {
                ArchiveAEExtension arcAE = ae.getAEExtension(ArchiveAEExtension.class);
                if (arcAE != null) {
                    rejectIfNoUserIdentity = arcAE.rejectIfNoUserIdentity();
                    userTypes = arcAE.userIdentityTypes();
                }
            }
        } else {
            // No device is a fatal authentication error
            LOG.error("Unable to get device for association");
            throw new AAssociateRJ(AAssociateRJ.RESULT_REJECTED_PERMANENT,
                    AAssociateRJ.SOURCE_SERVICE_USER,
                    AAssociateRJ.REASON_NO_REASON_GIVEN);
        }

        // All user types are supported unless otherwise specified
        if (userTypes.length < 1) {
            userTypes = new String[]{"username", "username_passcode", "saml", "kerberos", "jwt"};
        }

        ArchiveUserIdentityAC userIdentityAC = null;
        if (userIdentity != null) {
            switch (userIdentity.getType()) {
                case UserIdentityRQ.USERNAME_PASSCODE:
                    for (String type : userTypes) {
                        if (type.contentEquals("username_passcode")) {
                            userIdentityAC = negotiateUsernamePasscode(userIdentity.getUsername(),
                                    new String(userIdentity.getPasscode()),
                                    device, as);
                            break;
                        }
                    }
                    break;
                case UserIdentityRQ.USERNAME:
                    for (String type : userTypes) {
                        if (type.contentEquals("username")) {
                            userIdentityAC = negotiateUsername(userIdentity.getUsername(),
                                    device, as);
                            break;
                        }
                    }
                    break;
                case 5: // DICOM Standard JWT not yet added to org.dcm4che3.net.pdu.UserIdentityRQ
                    for (String type : userTypes) {
                        if (type.contentEquals("jwt")) {
                            userIdentityAC = negotiateJWT(new String(userIdentity.getPrimaryField()),
                                    device, as);
                            break;
                        }
                    }
                    break;
                case UserIdentityRQ.KERBEROS:
                    for (String type : userTypes) {
                        if (type.contentEquals("jwt")) {
                            userIdentityAC = negotiateKerberos(new String(userIdentity.getPrimaryField()),
                                    device, as);
                            break;
                        }
                    }
                    break;
                case UserIdentityRQ.SAML:
                    for (String type : userTypes) {
                        if (type.contentEquals("jwt")) {
                            userIdentityAC = negotiateSAML(new String(userIdentity.getPrimaryField()),
                                    device, as);
                            break;
                        }
                    }
                    break;
                default:
                    break;
            }
        } else {
            LOG.debug("User Identity negotiation without UserIdentityRQ");
        }

        if (userIdentityAC == null && rejectIfNoUserIdentity) {
            LOG.debug("Reject because no user identity.");
            throw new AAssociateRJ(AAssociateRJ.RESULT_REJECTED_PERMANENT,
                    AAssociateRJ.SOURCE_SERVICE_USER,
                    AAssociateRJ.REASON_NO_REASON_GIVEN);
        }

        return userIdentityAC;
    }

    protected Collection<KeycloakClient> getKeycloakClients(@NotNull Device device, @NotNull Association as) {
        Collection<KeycloakClient> result = new ArrayList<>(device.getWebApplications().size() + 1);
        String aetitle = as.getLocalAET();
        if (aetitle != null) {

            for (WebApplication webapp : device.getWebApplications()) {
                // Only use web applications with AETitle that matches the called AETitle and having AET service class
                if (aetitle.equals(webapp.getAETitle()) && webapp.containsServiceClass(DCM4CHEE_ARC_AET)) {
                    KeycloakClient keycloakClient = webapp.getKeycloakClient();
                    if (keycloakClient != null)
                        result.add(keycloakClient);
                }
            }
        }

        // Also add the UI keycloak client
        String authServerURL = System.getProperty("auth-server-url");
        if (authServerURL != null) {
            KeycloakClient keycloakClient = new KeycloakClient();
            keycloakClient.setKeycloakClientID(System.getProperty("ui-client-id", "dcm4chee-arc-ui"));
            keycloakClient.setKeycloakRealm(System.getProperty("realm-name", "dcm4che"));
            keycloakClient.setKeycloakServerURL(authServerURL);
            keycloakClient.setTLSAllowAnyHostname(false);
            keycloakClient.setTLSDisableTrustManager(false);
            result.add(keycloakClient);
        }

        return result;
    }
}
