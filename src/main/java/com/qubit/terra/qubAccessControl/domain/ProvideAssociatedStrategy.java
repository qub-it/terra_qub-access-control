package com.qubit.terra.qubAccessControl.domain;

import pt.ist.fenixframework.DomainObject;

public class ProvideAssociatedStrategy<T extends DomainObject> extends ProviderStrategy<T> {

    public ProvideAssociatedStrategy() {
        super("Provide all associated objects", profile -> profile.internalProvideObjects(),
                (profile, object) -> profile.provideObjects().contains(object));
    }

}
