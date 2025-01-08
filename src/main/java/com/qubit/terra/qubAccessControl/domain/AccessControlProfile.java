package com.qubit.terra.qubAccessControl.domain;

import java.lang.ref.SoftReference;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.qubit.terra.framework.services.ServiceProvider;
import com.qubit.terra.framework.services.accessControl.AccessControlProfileManagerService;
import com.qubit.terra.framework.services.accessControl.Permission;
import com.qubit.terra.framework.services.accessControl.Profile;
import com.qubit.terra.framework.services.context.ApplicationUser;
import com.qubit.terra.framework.services.versioning.VersioningInformationReader;
import com.qubit.terra.framework.tools.primitives.LocalizedString;
import com.qubit.terra.qubAccessControl.servlet.AccessControlBundle;

import pt.ist.fenixframework.Atomic;
import pt.ist.fenixframework.Atomic.TxMode;
import pt.ist.fenixframework.DomainObject;
import pt.ist.fenixframework.FenixFramework;

public class AccessControlProfile extends AccessControlProfile_Base implements Profile {

    static final private Cache<AccessControlProfile, Set<? extends DomainObject>> CACHE =
            CacheBuilder.newBuilder().concurrencyLevel(Runtime.getRuntime().availableProcessors()).maximumSize(10000)
                    .expireAfterWrite(24, TimeUnit.HOURS).build();

    static final private Cache<String, Optional<AccessControlProfile>> PROFILE_CACHE =
            CacheBuilder.newBuilder().concurrencyLevel(Runtime.getRuntime().availableProcessors()).maximumSize(10 * 1000)
                    .expireAfterWrite(2, TimeUnit.HOURS).build();

    private transient SoftReference<Set<String>> parsedObjectIDs;

    protected AccessControlProfile() {
        super();
        setDomainRoot(pt.ist.fenixframework.FenixFramework.getDomainRoot());
    }

    protected AccessControlProfile(String rawName, LocalizedString description, String code, String customExpression,
            String customExpressionValidator, Boolean restricted, Boolean system, String objectsClass) {
        this();
        setRawName(rawName);
        setDescription(description);
        setCode(code);
        setCustomExpression(customExpression);
        setCustomExpressionValidator(customExpressionValidator);
        setRestricted(restricted);
        setSystem(system);
        setObjectsClass(objectsClass);
        checkRules();
        PROFILE_CACHE.put(code, Optional.of(this));
    }

    protected AccessControlProfile(String rawName, LocalizedString description, String customExpression,
            String customExpressionValidator, Boolean restricted, Boolean system, String objectsClass) {
        this();
        setRawName(rawName);
        setDescription(description);
        setCode(UUID.randomUUID().toString());
        setCustomExpression(customExpression);
        setCustomExpressionValidator(customExpressionValidator);
        setRestricted(restricted);
        setSystem(system);
        setObjectsClass(objectsClass);
        checkRules();
        PROFILE_CACHE.put(getCode(), Optional.of(this));
    }

    @Deprecated
    public static AccessControlProfile create(String rawName, LocalizedString description, String code, String customExpression,
            String customExpressionValidator, Boolean restricted, Boolean system, String objectsClass,
            String objectsProviderStrategy) {
        return create(rawName, description, code, customExpression, customExpressionValidator, restricted, system, objectsClass);
    }

    public static AccessControlProfile create(String rawName, LocalizedString description, String code, String customExpression,
            String customExpressionValidator, Boolean restricted, Boolean system, String objectsClass) {
        if (code == null) {
            return new AccessControlProfile(rawName, description, customExpression, customExpressionValidator, restricted, system,
                    objectsClass);
        } else if (findByCode(code) != null) {
            throw new IllegalArgumentException(AccessControlBundle.get("error.AccessControlProfile.code.exists", code));
        }
        return new AccessControlProfile(rawName, description, code, customExpression, customExpressionValidator, restricted,
                system, objectsClass);
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

        if (getSystem() == null) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlProfile.system.required"));
        }

        if (StringUtils.isNotBlank(getCustomExpression()) && StringUtils.isBlank(getCustomExpressionValidator())) {
            throw new IllegalStateException(
                    AccessControlBundle.get("error.AccessControlProfile.customExpressionValidator.required"));
        }
    }

    public static AccessControlProfile findByName(String name) {
        return findAll().stream().filter((AccessControlProfile p) -> p.getRawName().equals(name)).findFirst().orElse(null);
    }

    public static AccessControlProfile findByCode(String code) {
        try {
            AccessControlProfile result = PROFILE_CACHE.get(code, () -> lookup(code)).orElse(null);
            if (result != null && FenixFramework.isDomainObjectValid(result)) {
                return result;
            }
            PROFILE_CACHE.invalidate(code);
            return null;
        } catch (ExecutionException e) {
            return null;
        }
    }

    @Atomic(mode = TxMode.READ)
    private static Optional<AccessControlProfile> lookup(String code) {
        return findAll().stream().filter(op -> op.getCode().equals(code)).findFirst();
    }

    public static Set<AccessControlProfile> findAll() {
        return FenixFramework.getDomainRoot().getProfilesSet();
    }

    public boolean isRestricted() {
        return Boolean.TRUE.equals(getRestricted());
    }

    public boolean isSystem() {
        return Boolean.TRUE.equals(getSystem());
    }

    public boolean isAutoGenerated() {
        return Boolean.TRUE.equals(getAutoGenerated());
    }

    public Class getProviderClass() {
        String objectsClass = getObjectsClass();
        if (objectsClass != null) {
            try {
                return Class.forName(objectsClass);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("No class found for classname " + objectsClass, e);
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
            Gson gson = new GsonBuilder().create();
            JsonElement objectsJsonArray =
                    gson.toJsonTree(objects.stream().map(o -> o.getExternalId()).collect(Collectors.toList()));
            jsonObject.add(getProviderClass().getName(), objectsJsonArray);
            super.setObjects(jsonObject.toString());
        } else {
            super.setObjects("");
        }

        if (parsedObjectIDs != null) {
            parsedObjectIDs.clear();
        }
    }

    public <T extends DomainObject> void addAllObjects(Collection<T> objects) {
        Class providerClass = getProviderClass();
        if (providerClass == null) {
            throw new IllegalStateException("No object class defined");
        }
        Set<T> nonMatchingClassObjects =
                objects.parallelStream().filter(o -> !providerClass.isAssignableFrom(o.getClass())).collect(Collectors.toSet());
        if (nonMatchingClassObjects.isEmpty()) {
            Set<Object> finalObjects = provideObjects();
            finalObjects.addAll(objects);
            setObjects(finalObjects.stream().map(o -> (DomainObject) o).collect(Collectors.toSet()));
            objects.forEach(object -> ObjectProfilesCache.addToCache(object, this));
        } else {
            throw new IllegalArgumentException("Expected to receive collection of objects of type " + providerClass.getName());
        }
    }

    @Override
    public void addObject(Object object) {
        if (object instanceof DomainObject) {
            addObject((DomainObject) object);
        } else {
            throw new IllegalArgumentException("Can only add domain objects");
        }
    }

    public <T extends DomainObject> void addObject(T object) {
        Class providerClass = getProviderClass();
        if (providerClass == null) {
            throw new IllegalStateException("No object class defined");
        }
        if (providerClass.isAssignableFrom(object.getClass())) {
            Set<Object> objects = provideObjects();
            objects.add(object);
            setObjects(objects.stream().map(o -> (DomainObject) o).collect(Collectors.toSet()));
            ObjectProfilesCache.addToCache(object, this);
        } else {
            throw new IllegalArgumentException("Expected to receive object of type " + providerClass.getName()
                    + " but received object of type " + object.getClass().getName());
        }
    }

    public <T extends DomainObject> void removeAllObjects(Set<T> objects) {
        Class providerClass = getProviderClass();
        if (providerClass == null) {
            throw new IllegalStateException("No object class defined");
        }
        Set<T> nonMatchingClassObjects =
                objects.parallelStream().filter(o -> !providerClass.isAssignableFrom(o.getClass())).collect(Collectors.toSet());
        if (nonMatchingClassObjects.isEmpty()) {
            Set<Object> finalObjects = provideObjects();
            finalObjects.removeAll(objects);
            setObjects(finalObjects.stream().map(o -> (DomainObject) o).collect(Collectors.toSet()));
            objects.forEach(object -> ObjectProfilesCache.removeFromCache(object, this));
        } else {
            throw new IllegalArgumentException("Expected to receive collection of objects of type " + providerClass.getName());
        }
    }

    @Override
    public void removeObject(Object object) {
        if (object instanceof DomainObject) {
            removeObject((DomainObject) object);
        } else {
            throw new IllegalArgumentException("Can only remove domain objects");
        }

    }

    public void removeObject(DomainObject object) {
        Class providerClass = getProviderClass();
        if (providerClass == null) {
            throw new IllegalStateException("No object class defined");
        }
        if (providerClass.isAssignableFrom(object.getClass())) {
            Set<Object> objects = provideObjects();
            objects.remove(object);
            setObjects(objects.stream().map(o -> (DomainObject) o).collect(Collectors.toSet()));
            ObjectProfilesCache.removeFromCache(object, this);
        } else {
            throw new IllegalArgumentException("Expected to receive object of type " + providerClass.getName()
                    + " but received object of type " + object.getClass().getName());
        }
    }

    @Override
    public String getObjects() {
        throw new UnsupportedOperationException("Default method is disabled please use provideObjects().");
    }

    public <T extends DomainObject> Boolean containsObject(T object) {
        return provideObjects().contains(object);
    }

    private Set<String> parseObjectsJSONToStringArray() {
        if (parsedObjectIDs != null && parsedObjectIDs.get() != null) {
            return parsedObjectIDs.get();
        }

        Set<String> result = new HashSet<>();
        if (!StringUtils.isBlank(super.getObjects())) {
            JsonObject json = new Gson().fromJson(super.getObjects(), JsonObject.class);
            JsonArray objectsOIDArray = json.getAsJsonArray(getObjectsClass());
            objectsOIDArray.forEach(oid -> {
                result.add(oid.getAsString());
            });
        }
        parsedObjectIDs = new SoftReference<Set<String>>(result);

        return result;
    }

    public Set<Object> provideObjects() {
        Set<DomainObject> cacheResult = new HashSet<>();
        Set<String> oidsToRemove = new HashSet<>();
        Set<Object> result = new HashSet<>();
        try {
            cacheResult.addAll((Collection<? extends DomainObject>) CACHE.get(this, () -> parseObjectsJSON()));
        } catch (ExecutionException e) {
            return Collections.emptySet();
        }

        // We are checking if the object is valid because we
        // are persisting a weak reference to the object.
        // If the object is no longer valid we remove it from
        // the associated objects JSON.
        //
        // Daniel Pires - 29 April 2020
        //
        cacheResult.stream().forEach(object -> {

            if (isObjectValid(object)) {
                result.add(object);
            } else {
                oidsToRemove.add(object.getExternalId());
            }
        });

        // TODO: maybe lançar thread para apagar?
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
    private <T extends DomainObject> boolean isObjectValid(T object) {
        return FenixFramework.isDomainObjectValid(object);
    }

    private <T extends DomainObject> Set<T> parseObjectsJSON() {
        Set<T> result = new HashSet<>();
        Set<String> oids = new HashSet<>();
        if (!StringUtils.isBlank(super.getObjects())) {
            JsonObject json = new Gson().fromJson(super.getObjects(), JsonObject.class);
            JsonArray objectsOIDArray = json.getAsJsonArray(getObjectsClass());
            objectsOIDArray.forEach(oid -> {
                String oidAsString = oid.getAsString();
                result.add(FenixFramework.getDomainObject(oidAsString));
                oids.add(oidAsString);
            });
        }

        if (parsedObjectIDs != null) {
            parsedObjectIDs.clear();
        }

        parsedObjectIDs = new SoftReference<Set<String>>(oids);

        return result;
    }

    @Atomic
    private void cleanObjectsJSON(Set<String> oidsToRemove) {
        CACHE.invalidate(this);
        if (parsedObjectIDs != null) {
            parsedObjectIDs.clear();
        }
        String objects = super.getObjects();
        for (String oid : oidsToRemove) {
            objects = objects.replace("\"" + oid + "\"", "").replace(",,", ",").replace("[,", "[").replace(",]", "]");
        }
        super.setObjects(objects);
    }

    @pt.ist.fenixframework.Atomic
    public void delete() {
        if (isSystem()) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlProfile.delete.protected"));
        }
        if (!getParentSet().isEmpty()) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlProfile.delete")
                    + getParentSet().stream().map(profile -> profile.getRawName()).collect(Collectors.joining(",")));
        }

        getMembers().forEach(u -> this.removeMember(u));
        removeFromObjectsCache();

        getChildSet().forEach(child -> removeChild(child));
        getPermissionSet().forEach(permission -> removePermission(permission));

        setDomainRoot(null);

        PROFILE_CACHE.invalidate(getCode());
        super.deleteDomainObject();
    }

    @Override
    public void addParent(AccessControlProfile parent) {
        if (validate(parent)) {
            super.addParent(parent);
        }
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

    @Override
    public void setObjectsClass(String objectsClass) {
        removeFromObjectsCache();
        super.setObjectsClass(objectsClass);
        addToObjectsCache();
    }

    public void removeFromObjectsCache() {
        if (getProviderClass() == null) {
            return;
        }

        provideObjects().stream().map(object -> (DomainObject) object)
                .forEach(object -> ObjectProfilesCache.removeFromCache(object, this));
    }

    public void addToObjectsCache() {
        if (getProviderClass() == null) {
            return;
        }

        provideObjects().stream().map(object -> (DomainObject) object)
                .forEach(object -> ObjectProfilesCache.addToCache(object, this));
    }

    @Override
    public void setName(LocalizedString name) {
        setRawName(name.toString());
    }

    @Override
    public LocalizedString getName() {
        return new LocalizedString(getRawName());
    }

    @Override
    public Set<Profile> getParents() {
        return getParentSet().stream().collect(Collectors.toSet());
    }

    @Override
    public Set<Profile> getChilds() {
        return getChildSet().stream().collect(Collectors.toSet());
    }

    @Override
    public Set<Permission> getPermissions() {
        return getPermissionSet().stream().collect(Collectors.toSet());
    }

    @Override
    public DateTime getCreationDate() {
        return ServiceProvider.getService(VersioningInformationReader.class).getCreationDate(this);
    }

    @Override
    public Collection<ApplicationUser> getMembers() {
        return ServiceProvider.getService(AccessControlProfileManagerService.class).getMembers(this);
    }

    @Override
    public void removePermission(Permission permission) {
        removePermission((AccessControlPermission) permission);
    }

    @Override
    public void addChildProfile(Profile profile) {
        addChild((AccessControlProfile) profile);
    }

    @Override
    public void removeChildProfile(Profile profile) {
        removeChild((AccessControlProfile) profile);
    }

    @Override
    public void addPermission(Permission permission) {
        addPermission((AccessControlPermission) permission);
    }

}
