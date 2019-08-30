package com.qubit.terra.qubAccessControl.servlet;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import com.qubit.terra.qubAccessControl.domain.AccessControlOperationPermission;
import com.qubit.terra.qubAccessControl.domain.AccessControlProfile;
import com.qubit.terra.qubAccessControl.domain.AccessControlProfileType;

import pt.ist.fenixframework.Atomic;
import pt.ist.fenixframework.Atomic.TxMode;

@WebListener
public class QubAccessControlInitializer implements ServletContextListener {

        @Override
        public void contextInitialized(ServletContextEvent event) {
             initializeProfiles();
        }

        @Override
        public void contextDestroyed(ServletContextEvent event){
        }
        
        @Atomic(mode = TxMode.WRITE)
        private void initializeProfiles() {
            
            // The ProfileType must be initialized before
            // the profile.
            // The Profile initialize must execute
            // before OperationPermission initialize because
            // the OperationPermission.AUTHORIZATION_MANAGER has
            // to be associated with the Profile.manager.
            //
            // 21 August 2019 - Daniel Pires
            //
            AccessControlProfileType.initialize();
            AccessControlOperationPermission.initialize();
            AccessControlProfile.initialize();
        }
        
}