package com.qubit.terra.qubAccessControl.domain;

import java.util.Set;
import java.util.stream.Collectors;

import com.qubit.terra.qubAccessControl.servlet.AccessControlBundle;

import pt.ist.fenixframework.FenixFramework;

public class AccessControlPermission extends AccessControlPermission_Base {

	private static final String AUTHORIZATION_MANAGER = AccessControlBundle
			.accessControlBundle("AccessControlPermission.manager");

	static public AccessControlPermission manager() {
		return AccessControlPermission.findByCode(AUTHORIZATION_MANAGER);
	}

	static public void initialize() {
		if (findAll().isEmpty()) {
			create(AUTHORIZATION_MANAGER, true, AUTHORIZATION_MANAGER);
		}
	}

	protected AccessControlPermission() {
		super();
		setDomainRoot(pt.ist.fenixframework.FenixFramework.getDomainRoot());
	}

	protected AccessControlPermission(String rawName, Boolean restricted, String code) {
		this();
		setRawName(rawName);
		setRestricted(restricted);
		setCode(code);
		checkRules();
	}

	private void checkRules() {
		if (getDomainRoot() == null) {
			throw new IllegalStateException(AccessControlBundle.accessControlBundle("error.domainRoot.required"));
		}

		if (getRawName() == null) {
			throw new IllegalStateException(
					AccessControlBundle.accessControlBundle("error.AccessControlPermission.rawName.required"));
		}
		if (getRestricted() == null) {
			throw new IllegalStateException(
					AccessControlBundle.accessControlBundle("error.AccessControlPermission.restricted.required"));
		}
		if (getCode() == null) {
			throw new IllegalStateException(
					AccessControlBundle.accessControlBundle("error.AccessControlPermission.code.required"));
		}
	}

	public static AccessControlPermission create(String rawName, Boolean restricted, String code) {
		return new AccessControlPermission(rawName, restricted, code);
	}

	public static AccessControlPermission findByCode(String code) {
		return findAll().stream().filter(op -> op.getCode().equals(code)).findFirst().orElse(null);
	}

	public static Set<AccessControlPermission> findAll() {
		return FenixFramework.getDomainRoot().getPermissionsSet();
	}

	@pt.ist.fenixframework.Atomic
	public void delete() {
		if (!getProfileSet().isEmpty()) {
			throw new IllegalStateException(
					AccessControlBundle.accessControlBundle("error.AccessControlPermission.delete") + getProfileSet()
							.stream().map(profile -> profile.getRawName()).collect(Collectors.joining(",")));
		}

		setDomainRoot(null);
		super.deleteDomainObject();
	}

	public String getExpression() {
		return "permission(" + getCode() + ")";
	}

	public boolean isRestricted() {
		return getRestricted();
	}

}
