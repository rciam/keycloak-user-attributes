package org.rciam.plugins.user_attributes.helpers;

import jakarta.ws.rs.core.Response;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import java.util.List;
import java.util.Set;

public class Utils {
    private static final String USER_ATTRIBUTE_ROLES = "manage-user-attribute-";

    public static void hasUserAttributesRoles(AdminPermissionEvaluator realmAuth, List<String> requiredRoles, Set<String> userAttributeKeys) {
        userAttributeKeys.forEach(x -> requiredRoles.add((USER_ATTRIBUTE_ROLES + x)));
        if (realmAuth.adminAuth().getUser().getRoleMappingsStream().noneMatch(role -> role.isClientRole() && requiredRoles.contains(role.getName()))) {
            throw new ErrorResponseException("Not allowed", "Not allowed", Response.Status.FORBIDDEN);
        }
    }
}
