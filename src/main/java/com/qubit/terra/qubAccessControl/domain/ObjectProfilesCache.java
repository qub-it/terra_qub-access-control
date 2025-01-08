package com.qubit.terra.qubAccessControl.domain;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import pt.ist.fenixframework.DomainObject;

public class ObjectProfilesCache {

    // This cache does not work in cluster environments
    //
    // Daniel Pires && Rodrigo Neves - 19/02/2021

    static final private Cache<Object, Set<AccessControlProfile>> CACHE =
            CacheBuilder.newBuilder().concurrencyLevel(Runtime.getRuntime().availableProcessors()).build();
//                    .expireAfterWrite(20, TimeUnit.MINUTES).build();

    public static <T extends DomainObject> Set<AccessControlProfile> hasAccess(AccessControlPermission permission, T object) {

        Set<AccessControlProfile> profiles = new HashSet<>();
        try {
            profiles = CACHE.get(object, () -> loadCache(object));
        } catch (ExecutionException e) {
            e.printStackTrace();
        }

        return profiles.stream().filter(profile -> hasPermission(profile, permission)).collect(Collectors.toSet());
    }

    private static boolean hasPermission(AccessControlProfile profile, AccessControlPermission permission) {
        if (profile.getPermissionSet().contains(permission)) {
            return true;
        }

        return profile.getChildSet().stream().anyMatch(child -> hasPermission(child, permission));
    }

    public static <T extends DomainObject> boolean contains(AccessControlProfile profile, T object) {
        return getProfiles(object).contains(profile);
    }

    public static <T extends DomainObject> Set<AccessControlProfile> getProfiles(T object) {
        Set<AccessControlProfile> result = new HashSet<>();

        try {
            result.addAll(CACHE.get(object, () -> loadCache(object)));
        } catch (ExecutionException e) {
            e.printStackTrace();
        }

        return result;
    }

    public static <T extends DomainObject> void addToCache(T object, AccessControlProfile profile) {
        Set<AccessControlProfile> cachedProfiles = CACHE.getIfPresent(object);
        if (cachedProfiles != null) {
            cachedProfiles.add(profile);
        } else {
            cachedProfiles = new HashSet<>();
            cachedProfiles.add(profile);
            CACHE.put(object, cachedProfiles);
        }
    }

    public static <T extends DomainObject> void removeFromCache(T object, AccessControlProfile profile) {
        Set<AccessControlProfile> cachedProfiles = CACHE.getIfPresent(object);
        if (cachedProfiles != null) {
            cachedProfiles.remove(profile);

            if (cachedProfiles.isEmpty()) {
                CACHE.invalidate(object);
            }
        }
    }

    private static <T extends DomainObject> Set<AccessControlProfile> loadCache(T object) {
        return AccessControlProfile.findAll().stream()
                .filter(profile -> object.getClass().equals(profile.getProviderClass()) && profile.containsObject(object))
                .collect(Collectors.toSet());
    }

}
