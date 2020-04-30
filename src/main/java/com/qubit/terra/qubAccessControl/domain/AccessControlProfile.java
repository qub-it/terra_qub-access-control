package com.qubit.terra.qubAccessControl.domain;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.commons.lang.StringUtils;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.qubit.terra.qubAccessControl.servlet.AccessControlBundle;

import pt.ist.fenixframework.Atomic;
import pt.ist.fenixframework.Atomic.TxMode;
import pt.ist.fenixframework.DomainObject;
import pt.ist.fenixframework.FenixFramework;

public class AccessControlProfile extends AccessControlProfile_Base {

    static final private Cache<AccessControlProfile, Set<? extends DomainObject>> CACHE =
            CacheBuilder.newBuilder().concurrencyLevel(Runtime.getRuntime().availableProcessors()).maximumSize(10000)
                    .expireAfterWrite(24, TimeUnit.HOURS).build();

    protected AccessControlProfile() {
        super();
        setDomainRoot(pt.ist.fenixframework.FenixFramework.getDomainRoot());
    }

    protected AccessControlProfile(String rawName, String code, String customExpression, String customExpressionValidator,
            Boolean restricted, Boolean locked, String objectsClass, String objectsProviderStrategy) {
        this();
        setRawName(rawName);
        setCode(code);
        setCustomExpression(customExpression);
        setCustomExpressionValidator(customExpressionValidator);
        setRestricted(restricted);
        setLocked(locked);
        setObjectsClass(objectsClass);
        setObjectsProviderStrategy(objectsProviderStrategy);
        checkRules();
    }

    protected AccessControlProfile(String rawName, String customExpression, String customExpressionValidator, Boolean restricted,
            Boolean locked, String objectsClass, String objectsProviderStrategy) {
        this();
        setRawName(rawName);
        setCode(UUID.randomUUID().toString());
        setCustomExpression(customExpression);
        setCustomExpressionValidator(customExpressionValidator);
        setRestricted(restricted);
        setLocked(locked);
        setObjectsClass(objectsClass);
        setObjectsProviderStrategy(objectsProviderStrategy);
        checkRules();
    }

    public static AccessControlProfile create(String rawName, String code, String customExpression,
            String customExpressionValidator, Boolean restricted, Boolean locked, String objectsClass,
            String objectsProviderStrategy) {
        if (code == null) {
            return new AccessControlProfile(rawName, customExpression, customExpressionValidator, restricted, locked,
                    objectsClass, objectsProviderStrategy);
        } else if (findByCode(code) != null) {
            throw new IllegalArgumentException(AccessControlBundle.get("error.AccessControlProfile.code.exists", code));
        }
        return new AccessControlProfile(rawName, code, customExpression, customExpressionValidator, restricted, locked,
                objectsClass, objectsProviderStrategy);
    }

    private void checkRules() {
        if (getDomainRoot() == null) {
            throw new IllegalStateException(AccessControlBundle.get("error.domainRoot.required"));
        }

        if (getRawName() == null) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlProfile.name.required"));
        }

        if (getCode() == null) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlProfile.code.required"));
        }

        if (getRestricted() == null) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlProfile.manager.required"));
        }

        if (getLocked() == null) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlProfile.manager.required"));
        }
    }

    public static AccessControlProfile findByName(String name) {
        return findAll().stream().filter((AccessControlProfile p) -> p.getRawName().equals(name)).findFirst().orElse(null);
    }

    public static AccessControlProfile findByCode(String code) {
        return findAll().stream().filter((AccessControlProfile p) -> p.getCode().equals(code)).findFirst().orElse(null);
    }

    public static Set<AccessControlProfile> findAll() {
        return FenixFramework.getDomainRoot().getProfilesSet();
    }

    public Boolean isRestricted() {
        return getRestricted();
    }

    public Boolean isLocked() {
        return getLocked();
    }

    public Class getProviderClass() {
        String objectsClass = getObjectsClass();
        if (objectsClass != null) {
            try {
                return Class.forName(objectsClass);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("No class found for classname " + objectsClass);
            }
        }
        return null;
    }

    @Override
    public void setObjects(String objects) {
        throw new UnsupportedOperationException(
                "Default method is disabled please use addObject(object) or removeObject(object) to add or remove objects.");
    }

    private void setObjects(Set<? extends DomainObject> objects) {
        CACHE.put(this, objects);
        if (!objects.isEmpty()) {
            JsonObject jsonObject = new JsonObject();
            JsonArray jsonArray = new JsonArray();
            objects.forEach(object -> jsonArray.add(object.getExternalId()));
            jsonObject.add(getProviderClass().getName(), jsonArray);
            super.setObjects(jsonObject.toString());
        } else {
            super.setObjects("");
        }
    }

    public <T extends DomainObject> void addObject(T object) {
        Class providerClass = getProviderClass();
        if (providerClass == null) {
            throw new IllegalStateException("No object class defined");
        }
        if (providerClass.isAssignableFrom(object.getClass())) {
            Set<T> objects = provideObjects();
            objects.add(object);
            setObjects(objects);
        } else {
            throw new IllegalArgumentException("Expected to receive object of type " + providerClass.getName()
                    + " but received object of type " + object.getClass().getName());
        }
    }

    public <T extends DomainObject> void removeObject(T object) {
        Class providerClass = getProviderClass();
        if (providerClass == null) {
            throw new IllegalStateException("No object class defined");
        }
        if (providerClass.isAssignableFrom(object.getClass())) {
            Set<T> objects = provideObjects();
            objects.remove(object);
            setObjects(objects);
        } else {
            throw new IllegalArgumentException("Expected to receive object of type " + providerClass.getName()
                    + " but received object of type " + object.getClass().getName());
        }
    }

    @Override
    public String getObjects() {
        throw new UnsupportedOperationException("Default method is disabled please use provideObjects().");
    }

    private ProviderStrategy getProvider() {
        return ProviderStrategy.PROVIDERS.get(getObjectsProviderStrategy());
    }

    public <T extends DomainObject> Boolean containsObject(T object) {
        return getProvider().contains(this, object);
    }

    public <T extends DomainObject> Set<T> provideObjects() {
        return getProvider().provideAll(this);
    }

    protected <T extends DomainObject> Set<T> internalProvideObjects() {
        Set<T> cacheResult = new HashSet<>();
        Set<T> result = new HashSet<>();
        Set<String> oidsToRemove = new HashSet<>();
        try {
            cacheResult.addAll((Collection<? extends T>) CACHE.get(this, () -> parseObjectsJSON()));
        } catch (ExecutionException e) {
            return Collections.EMPTY_SET;
        }

        // We are checking if the object is valid because we
        // are persisting a weak reference to the object.
        // If the object is no longer valid we remove it from
        // the associated objects JSON.
        //
        // Daniel Pires - 29 April 2020
        //
        cacheResult.parallelStream().forEach(object -> {

            if (isOjectValid(object)) {
                result.add(object);
            } else {
                oidsToRemove.add(object.getExternalId());
            }
        });

        if (!oidsToRemove.isEmpty()) {
            cleanObjectsJSON(oidsToRemove);
        }

        return result;
    }

    // This method was created because it is used
    // on a parallel stream and we need that all
    // the generated threads run on Atomic Read
    // Mode.
    //
    // Daniel Pires - 30 April 2020
    //
    @Atomic(mode = TxMode.READ)
    private <T extends DomainObject> boolean isOjectValid(T object) {
        return FenixFramework.isDomainObjectValid(object);
    }

    private <T extends DomainObject> Set<T> parseObjectsJSON() {
        Set<T> result = new HashSet<>();
        if (!StringUtils.isBlank(super.getObjects())) {
            JsonObject json = new Gson().fromJson(super.getObjects(), JsonObject.class);
            JsonArray objectsOIDArray = json.get(getObjectsClass()).getAsJsonArray();
            objectsOIDArray.forEach(oid -> {
                result.add(FenixFramework.getDomainObject(oid.getAsString()));
            });
        }
        return result;
    }

    public <T extends DomainObject> Set<T> provideObjectsWithoutCache() {
        Class T = getProviderClass();
        Set<T> result = new HashSet<>();
        Set<String> oidsToRemove = new HashSet<>();
        if (!StringUtils.isBlank(super.getObjects())) {
            JsonObject json = new Gson().fromJson(super.getObjects(), JsonObject.class);
            JsonArray objectsOIDArray = json.get(getObjectsClass()).getAsJsonArray();
            objectsOIDArray.forEach(oid -> {
                DomainObject object = FenixFramework.getDomainObject(oid.getAsString());
                if (FenixFramework.isDomainObjectValid(object)) {
                    result.add((T) object);
                } else {
                    oidsToRemove.add(oid.getAsString());
                }
            });
        }
        if (!oidsToRemove.isEmpty()) {
            cleanObjectsJSON(oidsToRemove);
        }
        return result;
    }

    @Atomic
    private void cleanObjectsJSON(Set<String> oidsToRemove) {
        CACHE.invalidate(this);
        String objects = super.getObjects();
        for (String oid : oidsToRemove) {
            objects = objects.replace("\"" + oid + "\",", "").replace(", \"" + oid + "\"", "");
        }
        super.setObjects(objects);
    }

    @pt.ist.fenixframework.Atomic
    public void delete() {
        if (!getParentSet().isEmpty()) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlProfile.delete")
                    + getParentSet().stream().map(profile -> profile.getRawName()).collect(Collectors.joining(",")));
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
            throw new IllegalArgumentException(
                    AccessControlBundle.get("error.AccessControlProfile.addProfileToItself", getRawName()));
        }

        if (findAllParents().contains(child)) {
            throw new IllegalArgumentException(
                    AccessControlBundle.get("error.AccessControlProfile.treeCycle", getRawName(), child.getRawName()));
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
        profile.getParentSet().forEach(p -> parents.addAll(addParents(p)));
        return parents;
    }

}
