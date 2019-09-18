package com.qubit.terra.qubAccessControl.domain;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.qubit.terra.qubAccessControl.servlet.AccessControlBundle;

import pt.ist.fenixframework.FenixFramework;

public class AccessControlProfile extends AccessControlProfile_Base {

    private static final String MANAGER_CODE = AccessControlBundle.accessControlBundle("AccessControlProfile.manager.code");
    private static final String MANAGER_NAME = AccessControlBundle.accessControlBundle("AccessControlProfile.manager.name");

    static public AccessControlProfile manager() {
        return AccessControlProfile.findByCode(MANAGER_CODE);
    }
    
    static public void initialize() {
        if (findAll().isEmpty()) {
            final AccessControlProfile manager = create(MANAGER_NAME, MANAGER_CODE, "", false);
            manager.addPermission(AccessControlPermission.manager());
        }
    }

    protected AccessControlProfile() {
        super();
        setDomainRoot(pt.ist.fenixframework.FenixFramework.getDomainRoot());
    }
    
    protected AccessControlProfile(String name, String code, String customExpression, Boolean manager) {
    	this();
    	setName(name);
    	setCode(code);
    	setCustomExpression(customExpression);
    	setManager(manager);
    	checkRules();
    }
    
    protected AccessControlProfile(String name, String customExpression, Boolean manager) {
    	this();
    	setName(name);
    	setCode(UUID.randomUUID().toString());
    	setCustomExpression(customExpression);
    	setManager(manager);
    	checkRules();
    }
    
    public static AccessControlProfile create(String name, String code, String customExpression, Boolean manager) {
    	if(code == null) {
    		return new AccessControlProfile(name, customExpression, manager);
    	}
    	return new AccessControlProfile(name, code, customExpression, manager);
    }
    
    private void checkRules() {
    	if(getDomainRoot() == null) {
			throw new IllegalStateException(AccessControlBundle.accessControlBundle("error.domainRoot.required"));
		}
    	
		if(getName() == null) {
			throw new IllegalStateException(AccessControlBundle.accessControlBundle("error.AccessControlProfile.name.required"));
		}
		
		if(getCode() == null) {
			throw new IllegalStateException(AccessControlBundle.accessControlBundle("error.AccessControlProfile.code.required"));
		}
		
		if(getManager() == null) {
			throw new IllegalStateException(AccessControlBundle.accessControlBundle("error.AccessControlProfile.manager.required"));
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
    
    public Boolean isManager() {
    	return getManager();
    }

    @pt.ist.fenixframework.Atomic
    public void delete() {
        if (!getParentSet().isEmpty()) {
            throw new IllegalStateException(AccessControlBundle.accessControlBundle("error.AccessControlProfile.delete")
                    + getParentSet().stream().map(profile -> profile.getName()).collect(Collectors.joining(",")));
        }

        getChildSet().forEach(child -> removeChild(child));
        getPermissionSet().forEach(permission -> removePermission(permission));

        setDomainRoot(null);
        super.deleteDomainObject();
    }

    @Override
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
        	throw new IllegalArgumentException(AccessControlBundle.accessControlBundle("error.AccessControlProfile.addProfileToItself", getName()));
        }

        if (findAllParents().contains(child)) {
            throw new IllegalArgumentException(AccessControlBundle.accessControlBundle("error.AccessControlProfile.treeCycle", getName(), child.getName()));
        }

        return true;
    }


    public Set<AccessControlProfile> findAllParents() {
        Set<AccessControlProfile> parents = new HashSet<>();
        parents.addAll(addParents(this));
        return parents;
    }

    private Set<AccessControlProfile> addParents(AccessControlProfile profile) {
        Set<AccessControlProfile> parents = new HashSet<>();
        parents.addAll(profile.getParentSet());
        profile.getParentSet().forEach( p -> parents.addAll(addParents(p)));
        return parents;
    }
    

}
