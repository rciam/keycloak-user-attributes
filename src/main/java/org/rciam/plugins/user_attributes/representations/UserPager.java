package org.rciam.plugins.user_attributes.representations;

import org.keycloak.representations.account.UserRepresentation;

import java.util.List;

public class UserPager {

    private List<UserRepresentation> users;
    private int count;

    public UserPager(){}

    public UserPager(List<UserRepresentation> users, int count){
        this.users = users;
        this.count = count;
    }

    public List<UserRepresentation> getUsers() {
        return users;
    }

    public void setUsers(List<UserRepresentation> users) {
        this.users = users;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }
}
