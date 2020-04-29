package com.qubit.terra.qubAccessControl.domain;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

public abstract class ProviderStrategy<T extends Object> {

    private String name;
    private Function<AccessControlProfile, Set<T>> provideFunction;
    private BiFunction<AccessControlProfile, T, Boolean> containsFunction;

    public ProviderStrategy(String name, Function<AccessControlProfile, Set<T>> provideFunction,
            BiFunction<AccessControlProfile, T, Boolean> containsFunction) {
        this.name = name;
        this.provideFunction = provideFunction;
        this.containsFunction = containsFunction;
    }

    public Set<T> provideAll(AccessControlProfile profile) {
        return this.provideFunction.apply(profile);
    }

    public Boolean contains(AccessControlProfile profile, T object) {
        return this.containsFunction.apply(profile, object);
    }

    public String getName() {
        return this.name;
    }

    public static Map<String, ProviderStrategy> PROVIDERS = new HashMap<String, ProviderStrategy>();

    static {

        // All objects of one type are valid
        ProviderStrategy<?> ALL_OF_CLASS = new ProvideAllOfClassStrategy<>();
        PROVIDERS.put(ALL_OF_CLASS.getClass().getName(), ALL_OF_CLASS);

        // All objects of the type or sub types are valid
        ProviderStrategy<?> ALL_OF_CLASS_AND_SUB_CLASSES = new ProvideAllOfClassAndSubClassStrategy<>();
        PROVIDERS.put(ALL_OF_CLASS_AND_SUB_CLASSES.getClass().getName(), ALL_OF_CLASS_AND_SUB_CLASSES);

        // Only the associated objects are valid
        ProviderStrategy<?> ASSOCIATED = new ProvideAssociatedStrategy<>();
        PROVIDERS.put(ASSOCIATED.getClass().getName(), ASSOCIATED);
    }
}
