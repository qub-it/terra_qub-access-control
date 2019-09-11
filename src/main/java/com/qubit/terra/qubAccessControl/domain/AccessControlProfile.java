package com.qubit.terra.qubAccessControl.domain;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import pt.ist.fenixframework.Atomic;
import pt.ist.fenixframework.Atomic.TxMode;
import pt.ist.fenixframework.FenixFramework;

public class AccessControlProfile extends AccessControlProfile_Base {

    private static final String MANAGER = "manager";

    static public AccessControlProfile manager() {
        return AccessControlProfile.findByCode(MANAGER);
    }

    static public void initialize() {
        if (AccessControlProfile.manager() == null) {
            final AccessControlProfile manager = new AccessControlProfile();
            manager.setName("Gestor de Permissoes");
            manager.setCode(MANAGER);
            manager.setType(AccessControlProfileType.findByName(MANAGER));
            manager.addPermission(AccessControlPermission.AUTHORIZATION_MANAGER());
        }
    }

    public AccessControlProfile() {
        super();
        setDomainRoot(pt.ist.fenixframework.FenixFramework.getDomainRoot());
    }

    // This method makes it possible to create 
    // a random unique identifier for the profile.
    // It doesn't override the setCode method so it's
    // possible to create a custom code.
    //
    // 27 August 2019 - Daniel Pires
    //
    public void setUUIDCode() {
        super.setCode(UUID.randomUUID().toString());
    }

    @Override
    public void setName(String name) {
        super.setName(name);
        if (super.getCode() == null || super.getCode().isEmpty()) {
            setUUIDCode();
        }
    }

    public static AccessControlProfile findByName(String name) {
        return findAll().stream().filter((AccessControlProfile p) -> p.getName().equals(name)).findFirst().orElse(null);
    }

    public static AccessControlProfile findByCode(String code) {
        return findAll().stream().filter((AccessControlProfile p) -> p.getCode().equals(code)).findFirst().orElse(null);
    }

    public static Set<AccessControlProfile> findAll() {
        return FenixFramework.getDomainRoot().getProfilesSet();
    }

    @pt.ist.fenixframework.Atomic
    public void delete() {
        if (!getParentSet().isEmpty()) {
            throw new IllegalStateException("You cannot delete a profile that has parent profiles. Parent profiles are: {0}"
                    + getParentSet().stream().map(profile -> profile.getName()).collect(Collectors.joining(",")));
        }

        getChildSet().forEach(child -> removeChild(child));
        getPermissionSet().forEach(permission -> removePermission(permission));

        setDomainRoot(null);
        setType(null);
        super.deleteDomainObject();
    }

    @Override
    @pt.ist.fenixframework.Atomic
    public void addChild(AccessControlProfile child) {
        if (validate(child)) {
            super.addChild(child);
        }
    }

    private boolean validate(AccessControlProfile child) {

        // Rules to be able to validate
        // 
        // 1. Profile cannot be added as a child of itself
        // 2. A profile child cannot be added this profile if 
        // there's a parentProfile path starting in this profile that reaches child 
        //
        // 14 August 2019 - Paulo Abrantes && Daniel Pires

        if (child == this) {
            throw new IllegalArgumentException("Unable to add profile " + getName() + " to itself");
        }

        if (findAllParents().contains(child)) {
            throw new IllegalArgumentException("Unable to add profile " + child.getName() + " to " + getName() + " because "
                    + getName() + " is already a parent of" + child.getName());
        }

        return true;
    }

    private void addParents(Set<AccessControlProfile> setOfParents, AccessControlProfile profile) {
        setOfParents.addAll(profile.getParentSet());
        profile.getParentSet().forEach(p -> addParents(setOfParents, p));
    }

    public Set<AccessControlProfile> findAllParents() {
        Set<AccessControlProfile> parents = new HashSet<>();
        addParents(parents, this);
        return parents;
    }

    @Override
    @Atomic(mode = TxMode.WRITE)
    public void addPermission(AccessControlPermission permission) {
        super.addPermission(permission);
    }

    @Override
    @Atomic(mode = TxMode.WRITE)
    public void removePermission(AccessControlPermission permission) {
        super.removePermission(permission);
    }

    @Override
    @Atomic(mode = TxMode.WRITE)
    public void addParent(AccessControlProfile parent) {
        super.addParent(parent);
    }

    @Override
    @Atomic(mode = TxMode.WRITE)
    public void removeParent(AccessControlProfile parent) {
        super.removeParent(parent);
    }

    @Override
    @Atomic(mode = TxMode.WRITE)
    public void removeChild(AccessControlProfile child) {
        super.removeChild(child);
    }
}
