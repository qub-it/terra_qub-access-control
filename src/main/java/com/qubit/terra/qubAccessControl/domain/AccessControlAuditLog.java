package com.qubit.terra.qubAccessControl.domain;

import java.util.Optional;

import org.joda.time.DateTime;

import com.qubit.terra.framework.services.context.ApplicationUser;

import pt.ist.fenixframework.FenixFramework;

public class AccessControlAuditLog extends AccessControlAuditLog_Base {

    public static final String PERMISSION_ADDED = "PERMISSION_ADDED";
    public static final String PERMISSION_REMOVED = "PERMISSION_REMOVED";
    public static final String MEMBER_ADDED = "MEMBER_ADDED";
    public static final String MEMBER_REMOVED = "MEMBER_REMOVED";
    public static final String OBJECT_ADDED = "OBJECT_ADDED";
    public static final String OBJECT_REMOVED = "OBJECT_REMOVED";
    public static final String CHILD_PROFILE_ADDED = "CHILD_PROFILE_ADDED";
    public static final String CHILD_PROFILE_REMOVED = "CHILD_PROFILE_REMOVED";
    public static final String PARENT_PROFILE_ADDED = "PARENT_PROFILE_ADDED";
    public static final String PARENT_PROFILE_REMOVED = "PARENT_PROFILE_REMOVED";
    protected static final String SYSTEM_OPERATION = "SYSTEM_OPERATION";

    private static final ThreadLocal<Boolean> auditEnabled = ThreadLocal.withInitial(() -> true);

    public static void suppressAudit() {
        auditEnabled.set(false);
    }

    public static void resumeAudit() {
        auditEnabled.set(true);
    }

    public static boolean isAuditEnabled() {
        return Boolean.TRUE.equals(auditEnabled.get());
    }

    public void delete() {
        super.setProfile(null);
        super.setDomainRoot(null);
        super.deleteDomainObject();
    }

    private AccessControlAuditLog(AccessControlProfile profile, String actionType, String target, String targetIdentifier) {
        super();
        setDomainRoot(FenixFramework.getDomainRoot());
        setLogDate(DateTime.now());
        setProfile(profile);
        setActionType(actionType);
        setTarget(target);
        setTargetIdentifier(targetIdentifier);
        final ApplicationUser currentApplicationUser = ApplicationUser.getCurrentApplicationUser();
        setActorUsername(Optional.ofNullable(currentApplicationUser).map(ApplicationUser::getUsername).orElse(SYSTEM_OPERATION));
        setActorName(Optional.ofNullable(currentApplicationUser).map(ApplicationUser::getName).orElse(SYSTEM_OPERATION));
    }

    public static void log(AccessControlProfile profile, String actionType, String target, String targetIdentifier) {
        if (!isAuditEnabled()) {
            return;
        }
        new AccessControlAuditLog(profile, actionType, target, targetIdentifier);
    }

}
