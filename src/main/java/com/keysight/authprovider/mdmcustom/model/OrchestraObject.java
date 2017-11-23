package com.keysight.authprovider.mdmcustom.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(value = { "childObjects","dbPrimaryKey" })
public class OrchestraObject {
    private Map<String,OrchestraContent> content;

    List<OrchestraObject> childObjects;

    private Integer dbPrimaryKey;

    public Map<String, OrchestraContent> getContent() {
        return content;
    }

    public void setContent(Map<String, OrchestraContent> content) {
        this.content = content;
    }

    public List<OrchestraObject> getChildObjects() {
        return childObjects;
    }

    public void setChildObjects(List<OrchestraObject> childObjects) {
        this.childObjects = childObjects;
    }

    public Integer getDbPrimaryKey() {
        return dbPrimaryKey;
    }

    public void setDbPrimaryKey(Integer dbPrimaryKey) {
        this.dbPrimaryKey = dbPrimaryKey;
    }

    @Override
    public String toString() {
        return "OrchestraObject{" +
                "content=" + content +
                ", childObjects=" + childObjects +
                ", dbPrimaryKey=" + dbPrimaryKey +
                '}';
    }

/*    public static void main(String[] args) throws IOException {
        OrchestraObject testObject = new OrchestraObject();
        Map<String,OrchestraContent> fields = new HashMap<>();
        fields.put("gender",new OrchestraContent("M"));
        fields.put("firstName",new OrchestraContent("Ashish"));
        testObject.setContent(fields);
        StringWriter stringTestObject = new StringWriter();
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(stringTestObject, testObject);
        System.out.println("JSON is\n"+stringTestObject);
    }*/
}
