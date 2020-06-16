package org.dcm4chee.arc.keycloak;

import org.keycloak.representations.AccessToken;

import java.util.HashSet;
import java.util.Set;

public class AccessControlID {

    public static Set<String> generateAccessControlIDs(HttpServletRequestInfo request) {

        if (request != null && request.requestKSC != null) {
            return generateAccessControlIDs(request.requestKSC.getToken(), null);
        }

        return failure();
    }

    public static Set<String> generateAccessControlIDs(AccessToken token, String client_id) {
        if (token == null)
            return failure();

        String clientid = client_id == null
                ? (token.getOtherClaims().get("azp") == null
                ? System.getProperty("ui-client-id","dcm4chee-arc-ui")
                : token.getOtherClaims().get("azp").toString())
                : client_id;

        if (clientid == null)
            return failure();

        AccessToken.Access access = token.getResourceAccess(clientid);
        if (access == null)
            return failure();

        return access.getRoles();
    }

    private static Set<String> failure() {
        Set<String> accessControlIDs = new HashSet<>();
        accessControlIDs.add("AccessControlNone");
        return accessControlIDs;
    }
}
