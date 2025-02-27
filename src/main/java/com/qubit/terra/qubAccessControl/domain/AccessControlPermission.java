package com.qubit.terra.qubAccessControl.domain;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.joda.time.DateTime;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.qubit.terra.framework.services.ServiceProvider;
import com.qubit.terra.framework.services.accessControl.Permission;
import com.qubit.terra.framework.services.accessControl.Profile;
import com.qubit.terra.framework.services.versioning.VersioningInformationReader;
import com.qubit.terra.framework.tools.primitives.LocalizedString;
import com.qubit.terra.qubAccessControl.servlet.AccessControlBundle;

import pt.ist.fenixframework.Atomic;
import pt.ist.fenixframework.Atomic.TxMode;
import pt.ist.fenixframework.DomainObject;
import pt.ist.fenixframework.FenixFramework;

public class AccessControlPermission extends AccessControlPermission_Base implements Permission {

    static final private Cache<String, Optional<AccessControlPermission>> CACHE =
            CacheBuilder.newBuilder().concurrencyLevel(Runtime.getRuntime().availableProcessors()).maximumSize(10 * 1000)
                    .expireAfterWrite(2, TimeUnit.HOURS).build();

    protected AccessControlPermission() {
        super();
        setDomainRoot(pt.ist.fenixframework.FenixFramework.getDomainRoot());
    }

    protected AccessControlPermission(String rawName, LocalizedString description, Boolean restricted, String code) {
        this();
        setRawName(rawName);
        setDescription(description);
        setRestricted(restricted);
        setCode(code);
        checkRules();
        CACHE.put(code, Optional.of(this));
    }

    private void checkRules() {
        if (getDomainRoot() == null) {
            throw new IllegalStateException(AccessControlBundle.get("error.domainRoot.required"));
        }

        if (getRawName() == null) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlPermission.rawName.required"));
        }
        if (getRestricted() == null) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlPermission.restricted.required"));
        }
        if (getCode() == null) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlPermission.code.required"));
        }
    }

    public static AccessControlPermission create(String rawName, LocalizedString description, Boolean restricted, String code) {
        if (findByCode(code) == null) {
            return new AccessControlPermission(rawName, description, restricted, code);
        } else {
            throw new IllegalArgumentException(AccessControlBundle.get("error.AccessControlPermission.code.exists", code));
        }
    }

    public static AccessControlPermission create(String rawName, Boolean restricted, String code) {
        return create(rawName, new LocalizedString(), restricted, code);
    }

    public static AccessControlPermission findByCode(String code) {
        try {
            AccessControlPermission result = CACHE.get(code, () -> lookup(code)).orElse(null);
            if (result != null && FenixFramework.isDomainObjectValid(result)) {
                return result;
            }
            CACHE.invalidate(code);
            return null;
        } catch (ExecutionException e) {
            return null;
        }
    }

    @Atomic(mode = TxMode.READ)
    private static Optional<AccessControlPermission> lookup(String code) {
        return findAll().stream().filter(op -> op.getCode().equals(code)).findFirst();
    }

    public static Set<AccessControlPermission> findAll() {
        return FenixFramework.getDomainRoot().getPermissionsSet();
    }

    @pt.ist.fenixframework.Atomic
    public void delete() {
        if (!getProfileSet().isEmpty()) {
            throw new IllegalStateException(AccessControlBundle.get("error.AccessControlPermission.delete")
                    + getProfileSet().stream().map(profile -> profile.getRawName()).collect(Collectors.joining(",")));
        }

        setDomainRoot(null);
        CACHE.invalidate(getCode());
        super.deleteDomainObject();
    }

    public String getExpression() {
        return "permission(" + getCode() + ")";
    }

    public boolean isRestricted() {
        return Boolean.TRUE.equals(getRestricted());
    }

    public boolean isAutoGenerated() {
        return Boolean.TRUE.equals(getAutoGenerated());
    }

    public <T extends DomainObject> Set<T> provideObjects() {
        return getProfileSet().stream().flatMap(profile -> profile.provideObjects().stream()).map(object -> (T) object)
                .collect(Collectors.toSet());
    }

    public <T extends DomainObject> Set<T> provideObjects(Class<T> clazz) {
        return getProfileSet().stream()
                .filter(profile -> profile.getProviderClass() != null && profile.getProviderClass().isAssignableFrom(clazz))
                .flatMap(profile -> profile.provideObjects().stream()).map(object -> (T) object).collect(Collectors.toSet());
    }

    @Override
    public Set<Profile> getProfiles() {
        return getProfileSet().stream().collect(Collectors.toSet());
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
    public DateTime getCreationDate() {
        return ServiceProvider.getService(VersioningInformationReader.class).getCreationDate(this);
    }

}
