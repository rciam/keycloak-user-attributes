# keycloak-user-attributes
A keycloak plugin to support extensions to admin User REST API

## Keycloak compatibility matrix
| User Attribute version | Keycloak version |
|------------------------|------------------|
| 1.0.0                  | 22.0.5 +         |
| 1.1.0                  | 22.0.13-1.17     |


## General configuration options 

In order to be able for a (service account) user to use REST API, appropriate realm-management roles need to be created and assigned to this user.
Roles have the format 'manage-user-attribute-{user_attribute_key}' . Fe 'manage-user-attribute-perunEntitlements'

## REST API

Main url : {server_url}/realms/{realm}/user-attributes

1) POST *{username}* with *username* being user username and body containing Map<String, List<String>> of user attributes to be updated.

2) GET *users/{attributeKey}* => get all users pager that have value of the user attribute *attributeKey*. 
User representation contains only username and attribute *attributeKey*.
