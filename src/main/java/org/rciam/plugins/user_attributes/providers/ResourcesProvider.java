/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.rciam.plugins.user_attributes.providers;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resource.RealmResourceProvider;
import jakarta.ws.rs.core.Context;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.rciam.plugins.user_attributes.helpers.AuthenticationHelper;
import org.rciam.plugins.user_attributes.helpers.Utils;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ResourcesProvider implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(ResourcesProvider.class);
    @Context
    protected ClientConnection clientConnection;

    private KeycloakSession session;
    private final RealmModel realm;
    private  final AdminPermissionEvaluator realmAuth;
    private final AdminEventBuilder adminEvent;

    public ResourcesProvider(KeycloakSession session) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.clientConnection = session.getContext().getConnection();
        AuthenticationHelper authHelper = new AuthenticationHelper(session);
        this.realmAuth = authHelper.authenticateRealmAdminRequest();
        this.adminEvent =  new AdminEventBuilder(realm, realmAuth.adminAuth(), session, clientConnection);
        adminEvent.realm(realm);
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    @POST
    @Path("/{username}")
    public Response updateUserAttribute(@PathParam("username") String username, Map<String, List<String>> attributes) {
        Utils.hasUserAttributesRoles(realmAuth, Stream.of(AdminRoles.ADMIN, AdminRoles.MANAGE_USERS).collect(Collectors.toList()), attributes.keySet());
        UserModel userChange = session.users().getUserByUsername(realm, username);
        if (userChange == null) {
            throw new ErrorResponseException("Could not find this user", "Could not find this user", Response.Status.NOT_FOUND);
        }
        attributes.entrySet().stream().forEach(entry -> userChange.setAttribute(entry.getKey(), entry.getValue()));
        StringBuilder sb = new StringBuilder("User with username ").append(username).append(" was updated ");
        attributes.entrySet().forEach(entry -> sb.append(" with key = ").append(entry.getKey()).append(" and value = ").append(entry.getValue()).append(","));
        logger.info(sb.toString());
        adminEvent.resource(ResourceType.USER).operation(OperationType.CREATE).representation(username).resourcePath(session.getContext().getUri()).success();

        return Response.noContent().build();
    }



}
