package org.dcm4chee.arc.keycloak;

import org.keycloak.representations.idm.authorization.Permission;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class AccessControlID {

    public static Set<String> generateAccessControlIDs(HttpServletRequestInfo request) {
        if (null != request) {
            if (null != request.requestKSC) {
                if (null != request.requestKSC.getAuthorizationContext()) {
                    return generateAccessControlIDs(request.requestKSC.getAuthorizationContext().getPermissions());
                }
            }
        }

        return Collections.emptySet();
    }

    public static Set<String> generateAccessControlIDs(List<Permission> permissionList) {
        Set<String> accessControlIDs = new HashSet<>();

        for (Permission permission : permissionList) {
            if (permission.getScopes().contains("accessControlID")) {
                accessControlIDs.add(permission.getResourceName());
            }
        }

        return accessControlIDs;
    }
}
