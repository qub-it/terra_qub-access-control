package com.qubit.terra.qubAccessControl.domain;

import java.util.Collections;

import pt.ist.fenixframework.DomainObject;

public class ProvideAllOfClassAndSubClassStrategy<T extends DomainObject> extends ProviderStrategy<T> {

    public ProvideAllOfClassAndSubClassStrategy() {
        super("Provide all objects of the associated class and sub classes", profile -> Collections.EMPTY_SET,
                (profile, object) -> profile.getProviderClass().isAssignableFrom(object.getClass()));
    }

}
