from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core import self_integrity
from app.core.config import Settings
from app.core.lineage import IntegrityLineage


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        report = self_integrity.check_self_integrity()
        configuration = settings or Settings.from_environment()
        from app.api.auth import initialize_auth
        from app.db.models import Base
        from app.db.session import create_database

        application.state.integrity = report
        application.state.settings = configuration
        application.state.lineage = IntegrityLineage()
        application.state.findings_registry = {}
        application.state.manifests_registry = {}
        application.state.assurance_registry = {}
        engine, factory = create_database(configuration.database_url)
        try:
            Base.metadata.create_all(engine)
            application.state.session_factory = factory
            initialize_auth(application)
            yield
        finally:
            engine.dispose()

    application = FastAPI(title="PRAMAAN", version="0.1.0", lifespan=lifespan)
    from app.api.assets import router as assets_router
    from app.api.auth import router as auth_router

    application.include_router(auth_router)
    application.include_router(assets_router)
    from app.api.passports import router as passports_router

    application.include_router(passports_router)
    from app.api.assessment import router as assessment_router

    application.include_router(assessment_router)
    origins = settings.cors_origins if settings else tuple(
        __import__("os").environ.get("CORS_ORIGINS", "http://localhost:5173").split(",")
    )
    application.add_middleware(
        CORSMiddleware, allow_origins=list(origins), allow_credentials=False,
        allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"],
    )

    @application.get("/api/health")
    def health():
        return {"status": "ok", "self_integrity": application.state.integrity.status}

    return application


app = create_app()
