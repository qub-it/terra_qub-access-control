package com.qubit.terra.qubAccessControl.domain;

import java.util.Optional;

import org.joda.time.DateTime;

import com.qubit.terra.framework.services.ServiceProvider;
import com.qubit.terra.framework.services.context.ApplicationUser;
import com.qubit.terra.framework.services.context.ApplicationUserProvider;

import pt.ist.fenixframework.FenixFramework;

public class AccessControlAuditLog extends AccessControlAuditLog_Base {

    private static final ThreadLocal<Boolean> auditEnabled = ThreadLocal.withInitial(() -> true);
    protected static final String SYSTEM = "SYSTEM";

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

    private AccessControlAuditLog(AccessControlProfile profile, AccessControlAuditLogType actionType, String target,
            String targetIdentifier) {
        super();
        setDomainRoot(FenixFramework.getDomainRoot());
        setLogDate(DateTime.now());
        setProfile(profile);
        setActionType(actionType);
        setTarget(target);
        setTargetIdentifier(targetIdentifier);
        final ApplicationUser applicationUser = Optional.ofNullable(ApplicationUser.getCurrentApplicationUser())
                .orElseGet(() -> ServiceProvider.getService(ApplicationUserProvider.class).getSystemUser());
        setActorUsername(Optional.ofNullable(applicationUser).map(ApplicationUser::getUsername).orElse(SYSTEM));
        setActorName(Optional.ofNullable(applicationUser).map(ApplicationUser::getName).orElse(SYSTEM));
    }

    public static void log(AccessControlProfile profile, AccessControlAuditLogType actionType, String target,
            String targetIdentifier) {
        if (!isAuditEnabled()) {
            return;
        }
        new AccessControlAuditLog(profile, actionType, target, targetIdentifier);
    }

}
