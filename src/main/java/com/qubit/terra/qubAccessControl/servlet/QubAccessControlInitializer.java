package com.qubit.terra.qubAccessControl.servlet;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

@WebListener
public class QubAccessControlInitializer implements ServletContextListener {

        @Override
        public void contextInitialized(ServletContextEvent event) {
             initializeProfiles();
        }

        @Override
        public void contextDestroyed(ServletContextEvent event){
        }
        
        private void initializeProfiles() {

        }
        
}