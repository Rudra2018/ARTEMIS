"""
FastAPI REST API for Automated Threat Modeling Agent

Provides RESTful endpoints for intelligent STRIDE-based threat modeling,
attack surface analysis, and automated risk assessment.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
import asyncio
import logging
from datetime import datetime

from .threat_modeling_agent import (
    ThreatModelingAgent, ThreatModel, Asset, ThreatVector,
    AttackPath, Mitigation, ThreatCategory, AssetType, RiskLevel
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Automated Threat Modeling Agent",
    description="Intelligent STRIDE-based threat modeling with attack surface analysis, automated risk assessment, and mitigation recommendations using graph neural networks",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Pydantic models for API
class SystemComponent(BaseModel):
    """System component definition"""
    name: str = Field(..., description="Component name")
    type: str = Field(..., description="Component type (e.g., 'web_service', 'database', 'api')")
    description: str = Field(default="", description="Component description")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Component properties")
    security_controls: List[str] = Field(default_factory=list, description="Existing security controls")
    trust_level: int = Field(default=5, ge=0, le=10, description="Trust level (0-10)")
    criticality: int = Field(default=5, ge=1, le=10, description="Business criticality (1-10)")
    internet_facing: bool = Field(default=False, description="Whether component is internet-facing")
    requires_authentication: bool = Field(default=True, description="Whether authentication is required")
    network_segmented: bool = Field(default=False, description="Whether component is network segmented")

class DataFlow(BaseModel):
    """Data flow definition"""
    name: str = Field(..., description="Data flow name")
    source: str = Field(..., description="Source component name")
    destination: str = Field(..., description="Destination component name")
    data_type: str = Field(..., description="Type of data being transferred")
    encryption: bool = Field(default=False, description="Whether data flow is encrypted")
    crosses_trust_boundary: bool = Field(default=False, description="Whether flow crosses trust boundaries")
    external_network: bool = Field(default=False, description="Whether flow goes over external network")
    trust_level: int = Field(default=5, ge=0, le=10, description="Data flow trust level")

class ExternalEntity(BaseModel):
    """External entity definition"""
    name: str = Field(..., description="External entity name")
    description: str = Field(default="", description="Entity description")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Entity properties")
    trust_level: int = Field(default=3, ge=0, le=10, description="Trust level for external entity")

class ArchitectureDescription(BaseModel):
    """Complete system architecture description"""
    components: List[SystemComponent] = Field(..., description="System components")
    data_flows: List[DataFlow] = Field(default_factory=list, description="Data flows between components")
    external_entities: List[ExternalEntity] = Field(default_factory=list, description="External entities")
    scope: str = Field(default="", description="Threat modeling scope")
    assumptions: List[str] = Field(default_factory=list, description="Modeling assumptions")
    out_of_scope: List[str] = Field(default_factory=list, description="Items out of scope")

    class Config:
        schema_extra = {
            "example": {
                "components": [
                    {
                        "name": "Web Frontend",
                        "type": "web_service",
                        "description": "React-based user interface",
                        "internet_facing": True,
                        "trust_level": 6,
                        "criticality": 7
                    },
                    {
                        "name": "API Gateway",
                        "type": "api_gateway",
                        "description": "Central API management",
                        "security_controls": ["rate_limiting", "authentication"],
                        "trust_level": 7,
                        "criticality": 8
                    },
                    {
                        "name": "User Database",
                        "type": "database",
                        "description": "PostgreSQL user data store",
                        "network_segmented": True,
                        "trust_level": 8,
                        "criticality": 9
                    }
                ],
                "data_flows": [
                    {
                        "name": "User Login",
                        "source": "Web Frontend",
                        "destination": "API Gateway",
                        "data_type": "authentication_credentials",
                        "encryption": True
                    }
                ],
                "external_entities": [
                    {
                        "name": "End Users",
                        "description": "Application users",
                        "trust_level": 3
                    }
                ]
            }
        }

class ThreatModelingRequest(BaseModel):
    """Request model for threat modeling operations"""
    system_name: str = Field(..., description="Target system name")
    description: str = Field(default="", description="System description")
    architecture: ArchitectureDescription = Field(..., description="System architecture")
    include_attack_paths: bool = Field(default=True, description="Include attack path analysis")
    include_mitigations: bool = Field(default=True, description="Include mitigation recommendations")
    risk_threshold: str = Field(default="medium", description="Minimum risk level to include")

class ThreatModelingResponse(BaseModel):
    """Response model for threat modeling operations"""
    session_id: str
    status: str
    message: str
    threat_model_id: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None
    execution_time: float = 0.0

class ThreatModelStatusResponse(BaseModel):
    """Threat modeling status response"""
    session_id: str
    status: str
    progress: Dict[str, Any]
    results_available: bool

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime
    version: str

# Global storage for threat modeling sessions
threat_modeling_sessions: Dict[str, Dict[str, Any]] = {}

@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Automated Threat Modeling Agent",
        "version": "1.0.0",
        "status": "active",
        "endpoints": {
            "model": "POST /model - Create threat model",
            "health": "GET /health - Health check",
            "status": "GET /status/{session_id} - Get modeling status",
            "report": "GET /report/{session_id} - Get detailed report",
            "docs": "GET /docs - API documentation"
        }
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(),
        version="1.0.0"
    )

@app.post("/model", response_model=ThreatModelingResponse)
async def create_threat_model(request: ThreatModelingRequest, background_tasks: BackgroundTasks):
    """
    Create comprehensive threat model for system architecture

    This endpoint performs intelligent threat modeling including:
    - STRIDE-based threat analysis
    - Attack surface identification
    - Attack path discovery using graph analysis
    - Risk assessment and prioritization
    - Automated mitigation recommendations
    """
    try:
        # Validate system architecture
        if not request.architecture.components:
            raise HTTPException(
                status_code=400,
                detail="System architecture must include at least one component"
            )

        # Create threat modeling agent
        agent = ThreatModelingAgent()
        session_id = agent.session_id

        # Store session info
        threat_modeling_sessions[session_id] = {
            "status": "running",
            "start_time": datetime.now(),
            "request": request.dict(),
            "agent": agent
        }

        logger.info(f"Starting threat modeling session {session_id} for {request.system_name}")

        try:
            # Convert request to architecture description dict
            architecture_dict = {
                "components": [comp.dict() for comp in request.architecture.components],
                "data_flows": [flow.dict() for flow in request.architecture.data_flows],
                "external_entities": [entity.dict() for entity in request.architecture.external_entities],
                "scope": request.architecture.scope,
                "assumptions": request.architecture.assumptions,
                "out_of_scope": request.architecture.out_of_scope
            }

            # Create threat model
            threat_model = await agent.create_threat_model(
                architecture_dict,
                request.system_name,
                request.description
            )

            # Update session with results
            threat_modeling_sessions[session_id].update({
                "status": "completed",
                "end_time": datetime.now(),
                "threat_model": threat_model
            })

            # Get threat model summary
            summary = agent.get_threat_model_summary(threat_model)

            # Calculate execution time
            execution_time = (datetime.now() - threat_modeling_sessions[session_id]["start_time"]).total_seconds()

            response = ThreatModelingResponse(
                session_id=session_id,
                status="completed",
                message=f"Threat modeling completed successfully. Identified {len(threat_model.threat_vectors)} threats across {len(threat_model.assets)} assets.",
                threat_model_id=threat_model.id,
                summary=summary,
                execution_time=execution_time
            )

            return response

        except Exception as e:
            # Update session with error
            threat_modeling_sessions[session_id].update({
                "status": "error",
                "end_time": datetime.now(),
                "error": str(e)
            })

            logger.error(f"Threat modeling session {session_id} failed: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Threat modeling operation failed: {str(e)}"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in threat modeling endpoint: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/status/{session_id}", response_model=ThreatModelStatusResponse)
async def get_threat_modeling_status(session_id: str):
    """
    Get status of a threat modeling session

    Returns the current status and progress of a threat modeling operation.
    """
    if session_id not in threat_modeling_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Threat modeling session {session_id} not found"
        )

    session = threat_modeling_sessions[session_id]

    progress = {
        "start_time": session["start_time"].isoformat(),
        "status": session["status"]
    }

    if "end_time" in session:
        progress["end_time"] = session["end_time"].isoformat()
        progress["duration"] = (session["end_time"] - session["start_time"]).total_seconds()

    if "error" in session:
        progress["error"] = session["error"]

    if "threat_model" in session:
        threat_model = session["threat_model"]
        progress.update({
            "assets_analyzed": len(threat_model.assets),
            "threats_identified": len(threat_model.threat_vectors),
            "attack_paths_found": len(threat_model.attack_paths),
            "mitigations_recommended": len(threat_model.mitigations)
        })

    return ThreatModelStatusResponse(
        session_id=session_id,
        status=session["status"],
        progress=progress,
        results_available="threat_model" in session
    )

@app.get("/report/{session_id}", response_model=Dict[str, Any])
async def get_detailed_threat_model(session_id: str):
    """
    Get detailed threat model report for a session

    Returns complete threat modeling report including all assets, threats,
    attack paths, and mitigation recommendations.
    """
    if session_id not in threat_modeling_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Threat modeling session {session_id} not found"
        )

    session = threat_modeling_sessions[session_id]

    if "threat_model" not in session:
        raise HTTPException(
            status_code=404,
            detail=f"No threat model available for session {session_id}"
        )

    threat_model = session["threat_model"]

    # Convert threat model to detailed dictionary
    detailed_report = {
        "threat_model": {
            "id": threat_model.id,
            "name": threat_model.name,
            "description": threat_model.description,
            "target_system": threat_model.target_system,
            "created_at": threat_model.created_at.isoformat(),
            "updated_at": threat_model.updated_at.isoformat(),
            "version": threat_model.version,
            "methodology": threat_model.methodology,
            "scope": threat_model.scope,
            "assumptions": threat_model.assumptions,
            "out_of_scope": threat_model.out_of_scope
        },
        "assets": [
            {
                "id": asset.id,
                "name": asset.name,
                "type": asset.asset_type.value,
                "description": asset.description,
                "properties": asset.properties,
                "security_controls": asset.security_controls,
                "trust_level": asset.trust_level,
                "exposure_level": asset.exposure_level,
                "criticality": asset.criticality
            }
            for asset in threat_model.assets
        ],
        "threat_vectors": [
            {
                "id": threat.id,
                "name": threat.name,
                "category": threat.category.value,
                "description": threat.description,
                "affected_assets": threat.affected_assets,
                "attack_techniques": threat.attack_techniques,
                "prerequisites": threat.prerequisites,
                "impact_rating": threat.impact_rating,
                "likelihood": threat.likelihood,
                "confidence": threat.confidence.value,
                "mitre_techniques": threat.mitre_techniques,
                "cwe_references": threat.cwe_references,
                "risk_score": threat.likelihood * threat.impact_rating
            }
            for threat in threat_model.threat_vectors
        ],
        "attack_paths": [
            {
                "id": path.id,
                "name": path.name,
                "description": path.description,
                "steps": path.steps,
                "total_risk_score": path.total_risk_score,
                "complexity": path.complexity,
                "required_privileges": path.required_privileges,
                "detection_difficulty": path.detection_difficulty,
                "target_assets": path.target_assets
            }
            for path in threat_model.attack_paths
        ],
        "mitigations": [
            {
                "id": mitigation.id,
                "name": mitigation.name,
                "description": mitigation.description,
                "type": mitigation.mitigation_type,
                "effectiveness": mitigation.effectiveness,
                "implementation_cost": mitigation.implementation_cost,
                "operational_impact": mitigation.operational_impact,
                "applicable_threats": mitigation.applicable_threats,
                "implementation_guidance": mitigation.implementation_guidance
            }
            for mitigation in threat_model.mitigations
        ],
        "risk_assessment": threat_model.risk_matrix
    }

    return detailed_report

@app.get("/sessions", response_model=Dict[str, Any])
async def list_threat_modeling_sessions():
    """
    List all threat modeling sessions

    Returns a summary of all threat modeling sessions with their status.
    """
    sessions_summary = {}

    for session_id, session_data in threat_modeling_sessions.items():
        summary = {
            "status": session_data["status"],
            "start_time": session_data["start_time"].isoformat(),
            "system_name": session_data["request"]["system_name"]
        }

        if "end_time" in session_data:
            summary["end_time"] = session_data["end_time"].isoformat()

        if "threat_model" in session_data:
            threat_model = session_data["threat_model"]
            summary.update({
                "threats_identified": len(threat_model.threat_vectors),
                "attack_paths_found": len(threat_model.attack_paths),
                "mitigations_recommended": len(threat_model.mitigations)
            })

        sessions_summary[session_id] = summary

    return {
        "total_sessions": len(sessions_summary),
        "sessions": sessions_summary
    }

@app.delete("/sessions/{session_id}")
async def delete_threat_modeling_session(session_id: str):
    """
    Delete a threat modeling session

    Removes a threat modeling session and its associated data.
    """
    if session_id not in threat_modeling_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Threat modeling session {session_id} not found"
        )

    del threat_modeling_sessions[session_id]

    return {
        "message": f"Threat modeling session {session_id} deleted successfully"
    }

@app.get("/methodologies", response_model=Dict[str, Any])
async def list_threat_modeling_methodologies():
    """
    List available threat modeling methodologies

    Returns information about available threat modeling approaches.
    """
    methodologies = {
        "STRIDE": {
            "name": "STRIDE",
            "description": "Microsoft's threat modeling methodology focusing on six categories",
            "categories": {
                "spoofing": "Impersonating something or someone else",
                "tampering": "Modifying data or code",
                "repudiation": "Claiming to have not performed an action",
                "information_disclosure": "Exposing information to unauthorized individuals",
                "denial_of_service": "Denying or degrading service availability",
                "elevation_of_privilege": "Gaining capabilities without proper authorization"
            },
            "supported": True
        },
        "PASTA": {
            "name": "Process for Attack Simulation and Threat Analysis",
            "description": "Risk-centric threat modeling methodology",
            "supported": False,
            "planned": True
        },
        "VAST": {
            "name": "Visual, Agile, and Simple Threat modeling",
            "description": "Scalable threat modeling for agile development",
            "supported": False,
            "planned": True
        }
    }

    return {
        "available_methodologies": list(methodologies.keys()),
        "methodologies": methodologies,
        "default_methodology": "STRIDE"
    }

@app.get("/categories", response_model=Dict[str, Any])
async def list_threat_categories():
    """
    List threat categories and their characteristics

    Returns detailed information about STRIDE threat categories.
    """
    categories = {}

    # Get STRIDE mappings from agent
    agent = ThreatModelingAgent()
    stride_mappings = agent.stride_mappings

    for category, info in stride_mappings.items():
        categories[category.value] = {
            "name": category.value.replace("_", " ").title(),
            "description": info["description"],
            "common_techniques": info["common_techniques"],
            "typical_targets": info["typical_targets"],
            "detection_methods": info["detection_methods"]
        }

    return {
        "threat_categories": categories,
        "methodology": "STRIDE",
        "total_categories": len(categories)
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.now().isoformat()
        }
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "details": str(exc),
            "timestamp": datetime.now().isoformat()
        }
    )

# Startup event
@app.on_event("startup")
async def startup_event():
    """Startup event handler"""
    logger.info("Automated Threat Modeling Agent API starting up...")
    logger.info("Available endpoints:")
    logger.info("  POST /model - Create threat model")
    logger.info("  GET /health - Health check")
    logger.info("  GET /status/{session_id} - Get modeling status")
    logger.info("  GET /report/{session_id} - Get detailed report")
    logger.info("  GET /sessions - List all sessions")
    logger.info("  GET /methodologies - List methodologies")
    logger.info("  GET /docs - API documentation")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event handler"""
    logger.info("Automated Threat Modeling Agent API shutting down...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)