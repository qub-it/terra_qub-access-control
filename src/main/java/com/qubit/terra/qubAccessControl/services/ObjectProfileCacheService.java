package com.qubit.terra.qubAccessControl.services;

import java.util.Set;
import java.util.function.Function;

public class ObjectProfileCacheService {

    private static Function<Class, Set<Class>> subClassesProvider;

    public static void registerSubClassesProvider(Function<Class, Set<Class>> subClassesProvider) {
        ObjectProfileCacheService.subClassesProvider = subClassesProvider;
    }

    public static Set<Class> getAllSubClasses(Class clazz) {
        return subClassesProvider.apply(clazz);
    }
}
