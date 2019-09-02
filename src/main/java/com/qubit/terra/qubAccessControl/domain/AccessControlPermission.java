package com.qubit.terra.qubAccessControl.domain;

import java.util.Set;
import java.util.stream.Collectors;


import pt.ist.fenixframework.Atomic;
import pt.ist.fenixframework.Atomic.TxMode;
import pt.ist.fenixframework.FenixFramework;

public class AccessControlPermission extends AccessControlPermission_Base {
    
    static public AccessControlPermission AUTHORIZATION_MANAGER() {
        return AccessControlPermission.findByCode("AUTHORIZATION_MANAGER");
    }

    static public void initialize() {
        if (AUTHORIZATION_MANAGER() == null) {
            final AccessControlPermission manager = new AccessControlPermission();
            manager.setCode("AUTHORIZATION_MANAGER");
        }
    }
    
    public AccessControlPermission() {
        super();
        setDomainRoot(pt.ist.fenixframework.FenixFramework.getDomainRoot());
    }
    
    public static AccessControlPermission findByCode(String code) {
        return findAll().stream()
                .filter(op -> op.getCode().equals(code)).findFirst().orElse(null);
    }
    
    public static Set<AccessControlPermission> findAll(){
        return FenixFramework.getDomainRoot().getPermissionsSet();
    }

    @pt.ist.fenixframework.Atomic
    public void delete() {

        if (!getProfileSet().isEmpty()) {
            throw new IllegalStateException("You cannot delete a Operation Permission that has profiles associated. The profiles associated are: " +
                    getProfileSet().stream().map(profile -> profile.getName()).collect(Collectors.joining(",")));
        }

        setDomainRoot(null);
        super.deleteDomainObject();
    }
    
    public String getExpression() {
        return "permission(" + getCode() + ")";
    }
    
    @Override
    @Atomic(mode = TxMode.WRITE)
    public void addProfile(AccessControlProfile profile) {
        super.addProfile(profile);
    }
    
    @Override
    @Atomic(mode = TxMode.WRITE)
    public void removeProfile(AccessControlProfile profile) {
        super.removeProfile(profile);
    }
    
}
