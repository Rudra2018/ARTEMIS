"""
FastAPI REST API for AI Compliance Checking Agent

Provides RESTful endpoints for intelligent regulatory compliance assessment
including GDPR, PCI-DSS, HIPAA, SOX, and ISO 27001/27002 compliance checking.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
import asyncio
import logging
from datetime import datetime

from .compliance_agent import (
    ComplianceAgent, ComplianceFramework, ComplianceResult, ComplianceGap,
    ComplianceStatus, RiskLevel, ControlCategory
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="AI Compliance Checking Agent",
    description="Intelligent regulatory compliance assessment for GDPR, PCI-DSS, HIPAA, SOX, and ISO 27001/27002 using AI-powered policy analysis and automated control mapping",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Pydantic models for API
class SystemConfiguration(BaseModel):
    """System configuration for compliance assessment"""
    organization: str = Field(..., description="Organization name")
    scope: str = Field(..., description="Assessment scope")
    system_type: str = Field(..., description="Type of system (e.g., 'web_application', 'payment_system')")
    data_types: List[str] = Field(..., description="Types of data processed")

    # Security configurations
    authentication: Dict[str, Any] = Field(default_factory=dict, description="Authentication settings")
    encryption: Dict[str, Any] = Field(default_factory=dict, description="Encryption configurations")
    access_control: Dict[str, Any] = Field(default_factory=dict, description="Access control settings")
    monitoring: Dict[str, Any] = Field(default_factory=dict, description="Monitoring and logging settings")
    incident_response: Dict[str, Any] = Field(default_factory=dict, description="Incident response procedures")

    # Framework-specific configurations
    privacy_features: Dict[str, Any] = Field(default_factory=dict, description="Privacy-related features")
    technical_safeguards: Dict[str, Any] = Field(default_factory=dict, description="Technical safeguards")
    administrative_controls: Dict[str, Any] = Field(default_factory=dict, description="Administrative controls")
    physical_security: Dict[str, Any] = Field(default_factory=dict, description="Physical security measures")

    # Additional configurations
    firewall: Dict[str, Any] = Field(default_factory=dict, description="Firewall configurations")
    network_security: Dict[str, Any] = Field(default_factory=dict, description="Network security settings")
    cryptographic_controls: Dict[str, Any] = Field(default_factory=dict, description="Cryptographic controls")
    policies: Dict[str, Any] = Field(default_factory=dict, description="Security policies")

    class Config:
        schema_extra = {
            "example": {
                "organization": "Acme Corporation",
                "scope": "Payment processing system",
                "system_type": "payment_system",
                "data_types": ["cardholder_data", "pii", "financial_data"],
                "authentication": {
                    "mfa_enabled": True,
                    "strong_passwords": True,
                    "session_management": True
                },
                "encryption": {
                    "at_rest": True,
                    "in_transit": True,
                    "key_management": True
                },
                "access_control": {
                    "rbac_implemented": True,
                    "least_privilege": True,
                    "regular_reviews": True
                },
                "monitoring": {
                    "logging_enabled": True,
                    "real_time_monitoring": True,
                    "audit_trails": True
                },
                "firewall": {
                    "enabled": True,
                    "configured": True,
                    "regularly_reviewed": True
                }
            }
        }

class Evidence(BaseModel):
    """Evidence documentation for compliance assessment"""
    policies_procedures: List[str] = Field(default_factory=list, description="Policy and procedure documents")
    technical_documentation: List[str] = Field(default_factory=list, description="Technical documentation")
    audit_reports: List[str] = Field(default_factory=list, description="Previous audit reports")
    training_records: List[str] = Field(default_factory=list, description="Training and awareness records")
    incident_logs: List[str] = Field(default_factory=list, description="Security incident logs")
    access_logs: List[str] = Field(default_factory=list, description="Access and authentication logs")
    monitoring_reports: List[str] = Field(default_factory=list, description="Security monitoring reports")
    penetration_test_reports: List[str] = Field(default_factory=list, description="Penetration testing reports")
    vulnerability_assessments: List[str] = Field(default_factory=list, description="Vulnerability assessment reports")
    compliance_certificates: List[str] = Field(default_factory=list, description="Existing compliance certificates")

    # Additional evidence types
    security_configurations: Dict[str, Any] = Field(default_factory=dict, description="Security configuration evidence")
    control_implementations: Dict[str, Any] = Field(default_factory=dict, description="Control implementation evidence")
    risk_assessments: List[str] = Field(default_factory=list, description="Risk assessment documentation")
    business_continuity_plans: List[str] = Field(default_factory=list, description="Business continuity documentation")

class ComplianceAssessmentRequest(BaseModel):
    """Request model for compliance assessment"""
    frameworks: List[ComplianceFramework] = Field(..., description="Compliance frameworks to assess")
    system_configuration: SystemConfiguration = Field(..., description="System configuration details")
    evidence: Evidence = Field(..., description="Supporting evidence and documentation")
    assessment_scope: str = Field(default="full", description="Scope of assessment")
    include_recommendations: bool = Field(default=True, description="Include remediation recommendations")
    generate_report: bool = Field(default=True, description="Generate comprehensive report")

class ComplianceAssessmentResponse(BaseModel):
    """Response model for compliance assessment"""
    session_id: str
    status: str
    message: str
    assessment_results: Optional[List[Dict[str, Any]]] = None
    overall_score: Optional[float] = None
    execution_time: float = 0.0

class ComplianceStatusResponse(BaseModel):
    """Compliance assessment status response"""
    session_id: str
    status: str
    progress: Dict[str, Any]
    results_available: bool

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime
    version: str

# Global storage for compliance assessment sessions
compliance_sessions: Dict[str, Dict[str, Any]] = {}

@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with API information"""
    return {
        "service": "AI Compliance Checking Agent",
        "version": "1.0.0",
        "status": "active",
        "endpoints": {
            "assess": "POST /assess - Perform compliance assessment",
            "health": "GET /health - Health check",
            "status": "GET /status/{session_id} - Get assessment status",
            "report": "GET /report/{session_id} - Get detailed report",
            "frameworks": "GET /frameworks - List supported frameworks",
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

@app.post("/assess", response_model=ComplianceAssessmentResponse)
async def assess_compliance(request: ComplianceAssessmentRequest, background_tasks: BackgroundTasks):
    """
    Perform comprehensive compliance assessment

    This endpoint performs intelligent compliance assessment including:
    - AI-powered policy analysis and control mapping
    - Multi-framework compliance checking (GDPR, PCI-DSS, HIPAA, SOX, ISO)
    - Automated gap analysis and risk assessment
    - Remediation recommendations and compliance roadmap
    - Real-time compliance monitoring insights
    """
    try:
        # Validate frameworks
        if not request.frameworks:
            raise HTTPException(
                status_code=400,
                detail="At least one compliance framework must be specified"
            )

        # Create compliance agent
        agent = ComplianceAgent()
        session_id = agent.session_id

        # Store session info
        compliance_sessions[session_id] = {
            "status": "running",
            "start_time": datetime.now(),
            "request": request.dict(),
            "agent": agent
        }

        logger.info(f"Starting compliance assessment session {session_id} for {request.system_configuration.organization}")

        try:
            assessment_results = []
            total_score = 0.0

            # Assess each framework
            for framework in request.frameworks:
                logger.info(f"Assessing compliance for {framework.value}")

                result = await agent.assess_compliance(
                    framework,
                    request.system_configuration.dict(),
                    request.evidence.dict()
                )

                assessment_results.append(result)
                total_score += result.compliance_score

            # Calculate overall score
            overall_score = total_score / len(request.frameworks) if request.frameworks else 0.0

            # Generate comprehensive report if requested
            comprehensive_report = None
            if request.generate_report:
                comprehensive_report = await agent.generate_compliance_report(assessment_results)

            # Update session with results
            compliance_sessions[session_id].update({
                "status": "completed",
                "end_time": datetime.now(),
                "results": assessment_results,
                "comprehensive_report": comprehensive_report,
                "overall_score": overall_score
            })

            # Calculate execution time
            execution_time = (datetime.now() - compliance_sessions[session_id]["start_time"]).total_seconds()

            # Prepare response
            response_results = []
            for result in assessment_results:
                response_results.append({
                    "framework": result.framework.value,
                    "overall_status": result.overall_status.value,
                    "compliance_score": result.compliance_score,
                    "requirements_assessed": result.requirements_assessed,
                    "requirements_compliant": result.requirements_compliant,
                    "gaps_identified": result.requirements_gaps,
                    "critical_gaps": sum(1 for gap in result.gaps if gap.risk_level == RiskLevel.CRITICAL),
                    "high_risk_gaps": sum(1 for gap in result.gaps if gap.risk_level == RiskLevel.HIGH),
                    "recommendations_count": len(result.recommendations)
                })

            response = ComplianceAssessmentResponse(
                session_id=session_id,
                status="completed",
                message=f"Compliance assessment completed for {len(request.frameworks)} frameworks. Overall score: {overall_score:.2%}",
                assessment_results=response_results,
                overall_score=overall_score,
                execution_time=execution_time
            )

            return response

        except Exception as e:
            # Update session with error
            compliance_sessions[session_id].update({
                "status": "error",
                "end_time": datetime.now(),
                "error": str(e)
            })

            logger.error(f"Compliance assessment session {session_id} failed: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Compliance assessment operation failed: {str(e)}"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in compliance assessment endpoint: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/status/{session_id}", response_model=ComplianceStatusResponse)
async def get_compliance_status(session_id: str):
    """
    Get status of a compliance assessment session

    Returns the current status and progress of a compliance assessment operation.
    """
    if session_id not in compliance_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Compliance assessment session {session_id} not found"
        )

    session = compliance_sessions[session_id]

    progress = {
        "start_time": session["start_time"].isoformat(),
        "status": session["status"]
    }

    if "end_time" in session:
        progress["end_time"] = session["end_time"].isoformat()
        progress["duration"] = (session["end_time"] - session["start_time"]).total_seconds()

    if "error" in session:
        progress["error"] = session["error"]

    if "results" in session:
        results = session["results"]
        progress.update({
            "frameworks_assessed": len(results),
            "overall_score": session.get("overall_score", 0.0),
            "total_gaps": sum(len(result.gaps) for result in results),
            "critical_gaps": sum(sum(1 for gap in result.gaps if gap.risk_level == RiskLevel.CRITICAL) for result in results)
        })

    return ComplianceStatusResponse(
        session_id=session_id,
        status=session["status"],
        progress=progress,
        results_available="results" in session
    )

@app.get("/report/{session_id}", response_model=Dict[str, Any])
async def get_detailed_compliance_report(session_id: str):
    """
    Get detailed compliance assessment report for a session

    Returns comprehensive compliance report including all assessment results,
    gap analysis, risk assessment, and remediation recommendations.
    """
    if session_id not in compliance_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Compliance assessment session {session_id} not found"
        )

    session = compliance_sessions[session_id]

    if "results" not in session:
        raise HTTPException(
            status_code=404,
            detail=f"No compliance assessment results available for session {session_id}"
        )

    results = session["results"]
    comprehensive_report = session.get("comprehensive_report")

    # Convert results to detailed dictionary
    detailed_report = {
        "session_info": {
            "session_id": session_id,
            "organization": session["request"]["system_configuration"]["organization"],
            "assessment_date": session["start_time"].isoformat(),
            "execution_time": (session["end_time"] - session["start_time"]).total_seconds() if "end_time" in session else None,
            "frameworks_assessed": [f.value for f in session["request"]["frameworks"]],
            "assessment_scope": session["request"]["assessment_scope"]
        },
        "assessment_results": [
            {
                "result_id": result.id,
                "framework": result.framework.value,
                "overall_status": result.overall_status.value,
                "compliance_score": result.compliance_score,
                "assessment_date": result.assessment_date.isoformat(),
                "requirements_summary": {
                    "total_assessed": result.requirements_assessed,
                    "compliant": result.requirements_compliant,
                    "gaps_identified": result.requirements_gaps,
                    "compliance_percentage": (result.requirements_compliant / result.requirements_assessed * 100) if result.requirements_assessed > 0 else 0
                },
                "gaps": [
                    {
                        "gap_id": gap.id,
                        "requirement_id": gap.requirement_id,
                        "description": gap.gap_description,
                        "risk_level": gap.risk_level.value,
                        "impact": gap.impact_description,
                        "remediation_recommendations": gap.remediation_recommendations,
                        "effort_estimate": gap.effort_estimate,
                        "assigned_to": gap.assigned_to,
                        "status": gap.status,
                        "target_resolution_date": gap.target_resolution_date.isoformat() if gap.target_resolution_date else None
                    }
                    for gap in result.gaps
                ],
                "recommendations": result.recommendations,
                "next_review_date": result.next_review_date.isoformat()
            }
            for result in results
        ],
        "comprehensive_analysis": comprehensive_report
    }

    return detailed_report

@app.get("/sessions", response_model=Dict[str, Any])
async def list_compliance_sessions():
    """
    List all compliance assessment sessions

    Returns a summary of all compliance assessment sessions with their status.
    """
    sessions_summary = {}

    for session_id, session_data in compliance_sessions.items():
        summary = {
            "status": session_data["status"],
            "start_time": session_data["start_time"].isoformat(),
            "organization": session_data["request"]["system_configuration"]["organization"],
            "frameworks": [f.value for f in session_data["request"]["frameworks"]]
        }

        if "end_time" in session_data:
            summary["end_time"] = session_data["end_time"].isoformat()

        if "results" in session_data:
            results = session_data["results"]
            summary.update({
                "overall_score": session_data.get("overall_score", 0.0),
                "total_gaps": sum(len(result.gaps) for result in results),
                "critical_gaps": sum(sum(1 for gap in result.gaps if gap.risk_level == RiskLevel.CRITICAL) for result in results)
            })

        sessions_summary[session_id] = summary

    return {
        "total_sessions": len(sessions_summary),
        "sessions": sessions_summary
    }

@app.delete("/sessions/{session_id}")
async def delete_compliance_session(session_id: str):
    """
    Delete a compliance assessment session

    Removes a compliance assessment session and its associated data.
    """
    if session_id not in compliance_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Compliance assessment session {session_id} not found"
        )

    del compliance_sessions[session_id]

    return {
        "message": f"Compliance assessment session {session_id} deleted successfully"
    }

@app.get("/frameworks", response_model=Dict[str, Any])
async def list_compliance_frameworks():
    """
    List supported compliance frameworks

    Returns information about all supported compliance frameworks and their requirements.
    """
    # Get framework information from agent
    agent = ComplianceAgent()
    frameworks_info = {}

    for framework, info in agent.frameworks.items():
        frameworks_info[framework.value] = {
            "name": info["name"],
            "version": info["version"],
            "applicability": info["applicability"],
            "key_principles": info["key_principles"],
            "requirements_count": len(info["requirements"]),
            "supported": True
        }

    return {
        "supported_frameworks": list(frameworks_info.keys()),
        "frameworks": frameworks_info,
        "total_frameworks": len(frameworks_info)
    }

@app.get("/frameworks/{framework}", response_model=Dict[str, Any])
async def get_framework_details(framework: str):
    """
    Get detailed information about a specific compliance framework

    Returns comprehensive information about requirements, controls, and assessment criteria.
    """
    try:
        framework_enum = ComplianceFramework(framework.lower())
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail=f"Compliance framework '{framework}' not supported"
        )

    agent = ComplianceAgent()
    framework_info = agent.frameworks[framework_enum]

    # Get detailed requirements information
    requirements_details = []
    for req in framework_info["requirements"]:
        requirements_details.append({
            "id": req.id,
            "title": req.title,
            "description": req.description,
            "category": req.category.value,
            "mandatory": req.mandatory,
            "section": req.section,
            "subsection": req.subsection,
            "control_objectives": req.control_objectives,
            "implementation_guidance": req.implementation_guidance,
            "evidence_required": req.evidence_required
        })

    return {
        "framework": framework_enum.value,
        "name": framework_info["name"],
        "version": framework_info["version"],
        "applicability": framework_info["applicability"],
        "key_principles": framework_info["key_principles"],
        "requirements": requirements_details,
        "total_requirements": len(requirements_details)
    }

@app.get("/categories", response_model=Dict[str, Any])
async def list_control_categories():
    """
    List control categories and their descriptions

    Returns information about security control categories used in compliance assessments.
    """
    categories = {}

    for category in ControlCategory:
        categories[category.value] = {
            "name": category.value.replace("_", " ").title(),
            "description": f"Controls related to {category.value.replace('_', ' ')}"
        }

    return {
        "control_categories": categories,
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
    logger.info("AI Compliance Checking Agent API starting up...")
    logger.info("Available endpoints:")
    logger.info("  POST /assess - Perform compliance assessment")
    logger.info("  GET /health - Health check")
    logger.info("  GET /status/{session_id} - Get assessment status")
    logger.info("  GET /report/{session_id} - Get detailed report")
    logger.info("  GET /frameworks - List supported frameworks")
    logger.info("  GET /sessions - List all sessions")
    logger.info("  GET /docs - API documentation")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event handler"""
    logger.info("AI Compliance Checking Agent API shutting down...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)