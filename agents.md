# terra_qub-access-control

## Scope
- **Group ID:** com.qubit.terra
- **Artifact ID:** qub-access-control
- **Version:** 2.6.0
- **Packaging:** jar

## Functionalities
This module provides an access control system for the Fenix Framework-based applications. It implements role-based access control (RBAC) with the following core functionalities:

- **Profile Management**: Create, read, update, and delete access control profiles (roles)
- **Permission Management**: Define and manage granular permissions that can be assigned to profiles
- **Profile Hierarchy**: Support parent-child relationships between profiles for permission inheritance
- **Object-Profile Association**: Associate domain objects with profiles to define object-level access control
- **Audit Logging**: Track all access control changes with detailed audit logs
- **Caching**: Implement Guava-based caching for profiles and object associations to optimize performance
- **Validation**: Enforce business rules for profile creation, modification, and deletion

## Screens/UI
This module does not contain UI components. It is a backend service module providing access control APIs and domain logic.

## Services
The module provides the following key domain classes:

### Core Domain Classes
1. **AccessControlProfile** - Main profile entity with caching, object management, and hierarchy support
2. **AccessControlPermission** - Permission entity that can be assigned to profiles
3. **AccessControlProfileType** - Enum for profile types
4. **AccessControlAuditLog** - Audit logging for access control changes
5. **AccessControlAuditLogType** - Enum for audit log types
6. **ObjectProfilesCache** - Cache management for object-profile associations

### Service Classes
- **QubAccessControlInitializer** - Servlet initializer for the access control module
- **AccessControlBundle** - Resource bundle handler for i18n support

## Coding Style
- **Language**: Java 8+
- **Framework**: Fenix Framework (Domain-Driven Design)
- **Patterns**: 
  - Repository pattern for data access
  - Cache pattern using Guava Cache
  - Factory method pattern for entity creation
- **Naming Conventions**:
  - Classes: PascalCase (e.g., `AccessControlProfile`)
  - Methods: camelCase (e.g., `findByCode`, `addObject`)
  - Constants: UPPER_SNAKE_CASE
- **Error Handling**: Custom exceptions with localized error messages
- **Logging**: Audit logging for all access control changes
- **Testing**: Unit tests with JUnit
- **Dependencies**: 
  - Guava for caching
  - Gson for JSON processing
  - Fenix Framework for domain model
