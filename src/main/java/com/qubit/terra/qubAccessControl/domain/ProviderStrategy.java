package com.qubit.terra.qubAccessControl.domain;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

public abstract class ProviderStrategy<T extends Object> {

    protected static final Map<String, ProviderStrategy> PROVIDERS = new HashMap<String, ProviderStrategy>();

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

    public static void registerProvider(String name, ProviderStrategy provider) {
        PROVIDERS.put(name, provider);
    }

    public static ProviderStrategy getProvider(String name) {
        return PROVIDERS.get(name);
    }

    public static Set<String> getProvidersKeys() {
        return PROVIDERS.keySet();
    }

    public static Set<ProviderStrategy> getProviders() {
        return new HashSet<>(PROVIDERS.values());
    }

}
