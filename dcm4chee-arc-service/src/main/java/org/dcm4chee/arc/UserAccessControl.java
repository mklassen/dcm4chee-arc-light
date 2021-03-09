package org.dcm4chee.arc;

import org.dcm4che3.net.Association;
import org.dcm4che3.net.pdu.AAssociateAC;
import org.dcm4che3.net.pdu.UserIdentityAC;

import org.dcm4chee.arc.keycloak.ClientRoles;
import org.dcm4chee.arc.keycloak.HttpServletRequestInfo;

import java.util.HashSet;
import java.util.Set;

public class UserAccessControl {
    public static String[] getAccessControlIDs(Set<String> arcAEAccessControlIDSet, HttpServletRequestInfo httpServletRequestInfo, Association requestAssociation) {

        Set<String> accessControlIDSet = new HashSet<>();

        // Assign roles found in the HTTP request, if any
        Set<String> httpRequestAccessControlIDset = ClientRoles.get(httpServletRequestInfo);
        if(httpRequestAccessControlIDset != null)
            accessControlIDSet.addAll(httpRequestAccessControlIDset);

        // Assign roles found in the DICOM association, if any
        if (null != requestAssociation)
        {
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

        // Filter roles to only include those that are defined for AE (if any are defined for AE)
        if(arcAEAccessControlIDSet.size() > 0)
            accessControlIDSet = ClientRoles.filterRoles(accessControlIDSet, arcAEAccessControlIDSet);

        if (accessControlIDSet.isEmpty()) {
            // The user has no client roles, so only '*' studies may be accessed
            // To ensure that at least one accessControlID is present so they do not see everything
            accessControlIDSet.add("*");
        }

        return accessControlIDSet.toArray(new String[0]);
    }
}
