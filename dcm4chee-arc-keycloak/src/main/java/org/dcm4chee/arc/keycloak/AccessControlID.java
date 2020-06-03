package org.dcm4chee.arc.keycloak;

import org.keycloak.representations.AccessToken;

import java.util.HashSet;
import java.util.Set;
import java.util.Objects;

public class AccessControlID {

    public static Set<String> generateAccessControlIDs(HttpServletRequestInfo request) {

        if (!Objects.isNull(request) && !Objects.isNull(request.requestKSC) && !Objects.isNull(request.requestKSC.getToken())) {
            return generateAccessControlIDs(request.requestKSC.getToken(), null);
        }

        return failure();
    }

    public static Set<String> generateAccessControlIDs(AccessToken token, String client_id) {
        String clientid = token.getOtherClaims().get("origin-clientid").toString();

        AccessToken.Access access = token.getResourceAccess(Objects.isNull(client_id) ? "dcm4chee-arc-ui" : client_id);
        if (Objects.isNull(access))
            return failure();

        return access.getRoles();
    }

    private static Set<String> failure() {
        Set<String> accessControlIDs = new HashSet<>();
        accessControlIDs.add("None");
        return accessControlIDs;
    }
}
