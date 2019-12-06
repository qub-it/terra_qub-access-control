package com.qubit.terra.qubAccessControl.domain;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.qubit.terra.qubAccessControl.servlet.AccessControlBundle;

import pt.ist.fenixframework.FenixFramework;

public class AccessControlPermission extends AccessControlPermission_Base {

    static final private Cache<String, Optional<AccessControlPermission>> CACHE =
            CacheBuilder.newBuilder().concurrencyLevel(4).maximumSize(10 * 1000).expireAfterWrite(2, TimeUnit.HOURS).build();

	private static final String AUTHORIZATION_MANAGER_NAME = AccessControlBundle
			.localizedString("AccessControlPermission.manager");

	private static final String AUTHORIZATION_MANAGER_CODE = AccessControlBundle.get("AccessControlPermission.manager");

	static public AccessControlPermission manager() {
		return AccessControlPermission.findByCode(AUTHORIZATION_MANAGER_CODE);
	}

	static public void initialize() {
		if (findAll().isEmpty()) {
			create(AUTHORIZATION_MANAGER_NAME, true, AUTHORIZATION_MANAGER_CODE, false);
		}
	}

	protected AccessControlPermission() {
		super();
		setDomainRoot(pt.ist.fenixframework.FenixFramework.getDomainRoot());
	}

	protected AccessControlPermission(String rawName, Boolean restricted, String code, Boolean locked) {
		this();
		setRawName(rawName);
		setRestricted(restricted);
		setCode(code);
		setLocked(locked);
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
			throw new IllegalStateException(
					AccessControlBundle.get("error.AccessControlPermission.restricted.required"));
		}
		if (getCode() == null) {
			throw new IllegalStateException(AccessControlBundle.get("error.AccessControlPermission.code.required"));
		}
		if (getLocked() == null) {
			throw new IllegalStateException(
					AccessControlBundle.get("error.AccessControlPermission.restricted.required"));
		}
	}

	public static AccessControlPermission create(String rawName, Boolean restricted, String code, Boolean locked) {
		if (findByCode(code) == null) {
			return new AccessControlPermission(rawName, restricted, code, locked);
		} else {
			throw new IllegalArgumentException(
					AccessControlBundle.get("error.AccessControlPermission.code.exists", code));
		}

	}

	public static AccessControlPermission findByCode(String code) {
        try {
            return CACHE.get(code, () -> findAll().stream().filter(op -> op.getCode().equals(code)).findFirst()).orElse(null);
        } catch (ExecutionException e) {
            return null;
        }
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
		super.deleteDomainObject();
        CACHE.invalidate(getCode());
	}

	public String getExpression() {
		return "permission(" + getCode() + ")";
	}

	public Boolean isRestricted() {
		return getRestricted();
	}

	public Boolean isLocked() {
		return getLocked();
	}
}
