package com.qubit.terra.qubAccessControl.domain;

import com.qubit.terra.framework.services.context.ApplicationUser;

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
        super.deleteDomainObject();
    }

    public static void log(AccessControlProfile profile, String actionType, String targetDescription,
            String targetIdentifier) {
        if (!isAuditEnabled()) {
            return;
        }

        ApplicationUser user = ApplicationUser.getCurrentApplicationUser();
        if (user == null) {
            return;
        }

        AccessControlAuditLog log = new AccessControlAuditLog();
        log.setProfile(profile);
        log.setActionType(actionType);
        log.setActorUsername(user.getUsername());
        log.setActorName(user.getName() != null ? user.getName() : user.getUsername());
        log.setTargetDescription(targetDescription);
        log.setTargetIdentifier(targetIdentifier);
        log.setTimestamp(System.currentTimeMillis());
    }
}
