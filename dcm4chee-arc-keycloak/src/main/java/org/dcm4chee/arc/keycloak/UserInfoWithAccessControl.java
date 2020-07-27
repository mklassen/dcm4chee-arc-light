package org.dcm4chee.arc.keycloak;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.keycloak.json.StringOrArrayDeserializer;
import org.keycloak.json.StringOrArraySerializer;
import org.keycloak.representations.UserInfo;

public class UserInfoWithAccessControl extends UserInfo {
    @JsonProperty("access_control")
    @JsonSerialize(using = StringOrArraySerializer.class)
    @JsonDeserialize(using = StringOrArrayDeserializer.class)
    protected String[] accessControl;

    @JsonIgnore
    public String[] getAccessControl() {
        return accessControl;
    }

    public void setAccessControl(String... accessControl) {
        this.accessControl = accessControl;
    }
}
