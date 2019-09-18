package com.qubit.terra.qubAccessControl.domain;

import java.util.Set;
import java.util.stream.Collectors;


import pt.ist.fenixframework.FenixFramework;

public class AccessControlProfileType extends AccessControlProfileType_Base {
    
    public static void initialize() {
        if (AccessControlProfileType.findByName("manager") == null) {
            AccessControlProfileType manager = new AccessControlProfileType();
            manager.setName("manager");
        }

        if (AccessControlProfileType.findByName("general") == null) {
            AccessControlProfileType general = new AccessControlProfileType();
            general.setName("general");
        }

        if (AccessControlProfileType.findByName("base") == null) {
            AccessControlProfileType base = new AccessControlProfileType();
            base.setName("base");
        }
    }
    
    public AccessControlProfileType() {
        super();
        setDomainRoot(pt.ist.fenixframework.FenixFramework.getDomainRoot());
    }
    
    public static AccessControlProfileType findByName(String name) {
        return findAll().stream()
                .filter(pt -> pt.getName().equals(name)).findFirst().orElse(null);
    }
    
    public static Set<AccessControlProfileType> findAll(){
        return FenixFramework.getDomainRoot().getProfileTypesSet();
    }
    
    
//    @pt.ist.fenixframework.Atomic
//    public void delete() {
//        if (!getProfilesSet().isEmpty()) {
//            throw new IllegalStateException("You cannot delete a profile type that has profiles associated. Associated profiles are: " +
//                    getProfilesSet().stream().map(profile -> profile.getName()).collect(Collectors.joining(",")));
//        }
//        setDomainRoot(null);
//        super.deleteDomainObject();
//    }
    
}
