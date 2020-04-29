package com.qubit.terra.qubAccessControl.domain;

import java.util.Collections;

import pt.ist.fenixframework.DomainObject;

public class ProvideAllOfClassStrategy<T extends DomainObject> extends ProviderStrategy<T> {

    public ProvideAllOfClassStrategy() {
        super("Provide all objects of the associated class", profile -> Collections.EMPTY_SET,
                (profile, object) -> object.getClass().equals(profile.getProviderClass()));
    }

}
