User Management System
FastAPI + async SQLAlchemy app for users, profiles, and roles.

What’s in here
Auth — /login/ (JWT bearer). Trailing slash aligned to avoid 307s.

Profiles — GET/PATCH /users/me accepts snake_case and common camelCase (displayName, profilePictureUrl → mapped).

Admin/Manager — CRUD on /users/ and role changes via PATCH /users/{id}/role

Admin can set any role.

Manager can’t assign ADMIN or change an ADMIN.

Run (Docker)
bash
Copy
Edit
docker compose up --build -d
# logs
docker compose logs -f fastapi
Docs: http://localhost:8000/docs

.env (example)
env
Copy
Edit
SECRET_KEY=dev-secret
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
POSTGRES_DB=user_management
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_HOST=db
POSTGRES_PORT=5432
MAX_LOGIN_ATTEMPTS=5
DB (when testing manually)
bash
Copy
Edit
docker compose exec fastapi alembic upgrade head
Quick API
Login

bash
Copy
Edit
curl -X POST http://localhost:8000/login/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=you@example.com&password=Pass$123"
Use token as Authorization: Bearer <token>.

Me (patch)

bash
Copy
Edit
curl -X PATCH http://localhost:8000/users/me \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"displayName":"new-nick","bio":"hi"}'
Role change (admin/manager)

bash
Copy
Edit
curl -X PATCH http://localhost:8000/users/<id>/role \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"role":"MANAGER"}'
Tests
bash
Copy
Edit
docker compose exec fastapi pytest -v
# optional coverage
docker compose exec fastapi pytest --cov=app -q
