#User Management System
FastAPI + async SQLAlchemy app for managing users, profiles, and roles.

#What I added
Profile Management upgrades – users can update their own profile fields smoothly (common naming styles handled).

RBAC role changes – admins and managers can change a user’s role with sensible guardrails.

#Tests
10 new tests exercising login flows, profile updates, and role-change authorization/edge cases.

#Tech & Status
FastAPI, async SQLAlchemy, JWT auth.

Dockerized; CI passing.