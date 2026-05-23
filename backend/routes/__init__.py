"""Aggregate API routers."""

from fastapi import APIRouter

from backend.routes.alert_routes import router as alert_router
from backend.routes.auth_routes import router as auth_router
from backend.routes.ai_routes import router as ai_router
from backend.routes.copilot_routes import router as copilot_router
from backend.routes.dashboard_routes import router as dashboard_router
from backend.routes.health_routes import router as health_router
from backend.routes.intel_routes import router as intel_router
from backend.routes.investigation_routes import router as investigation_router
from backend.routes.log_routes import router as log_router
from backend.routes.rule_routes import router as rule_router
from backend.routes.search_routes import router as search_router
from backend.routes.notification_routes import router as notification_router
from backend.routes.audit_routes import router as audit_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(alert_router)
api_router.include_router(log_router)
api_router.include_router(rule_router)
api_router.include_router(intel_router)
api_router.include_router(search_router)
api_router.include_router(investigation_router)
api_router.include_router(ai_router)
api_router.include_router(copilot_router)
api_router.include_router(dashboard_router)
api_router.include_router(health_router)
api_router.include_router(notification_router)
api_router.include_router(audit_router)
