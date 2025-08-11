import sys
sys.path.append('/app')

from app.main import app
from app.routers import user_routes

print("=== App Routes ===")
for route in app.routes:
    if hasattr(route, 'path'):
        methods = getattr(route, 'methods', set())
        print(f"{list(methods)} {route.path}")

print("\n=== User Router Routes ===")
if hasattr(user_routes, 'router'):
    for route in user_routes.router.routes:
        if hasattr(route, 'path'):
            methods = getattr(route, 'methods', set())
            print(f"{list(methods)} {route.path}")

print("\n=== Looking for PATCH routes ===")
for route in app.routes:
    if hasattr(route, 'path') and hasattr(route, 'methods'):
        if 'PATCH' in route.methods:
            print(f"Found PATCH: {route.methods} {route.path}")
