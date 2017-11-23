package com.keysight.authprovider.mdmcustom.model;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class OrchestraObjectStore {
    private List<OrchestraObject> orchestraObjects;


    public List<OrchestraObject> getAndRemove(int limit) {
        synchronized (orchestraObjects){
            List<OrchestraObject> objectsToReturn = orchestraObjects.stream().limit(limit).collect(Collectors.toList());
            orchestraObjects.removeAll(objectsToReturn);
            return objectsToReturn;
        }
    }

    public List<OrchestraObject> getAllAndRemove() {
        synchronized (orchestraObjects){
            List<OrchestraObject> objectsToReturn = new ArrayList<>(orchestraObjects);
            orchestraObjects.clear();
            return objectsToReturn;
        }
    }

    public void addAll(List<OrchestraObject> objectsToAdd){
        synchronized (orchestraObjects){
            if(orchestraObjects!=null){
                orchestraObjects.addAll(objectsToAdd);
            }else{
                orchestraObjects = new ArrayList<>();
                orchestraObjects.addAll(objectsToAdd);
            }
        }
    }

    public void add(OrchestraObject orchestraObjectToAdd){
        synchronized (orchestraObjects){
            if(orchestraObjects!=null){
                orchestraObjects.add(orchestraObjectToAdd);
            }else{
                orchestraObjects = new ArrayList<>();
                orchestraObjects.add(orchestraObjectToAdd);
            }
        }
    }
}
