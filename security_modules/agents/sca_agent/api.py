"""
FastAPI REST API for Software Composition Analysis (SCA) Agent

Provides RESTful endpoints for intelligent dependency scanning, vulnerability
detection, license compliance, and SBOM generation with real-time CVE monitoring.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
import asyncio
import logging
from datetime import datetime

from .sca_agent import (
    SCAAgent, VulnerabilityReport, Component, ComponentAnalysis,
    VulnerabilitySeverity, LicenseRisk, ComponentType, ScanStatus
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Software Composition Analysis Agent",
    description="Intelligent dependency scanning, vulnerability detection, license compliance, and SBOM generation using AI-powered component analysis and threat intelligence integration",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Pydantic models for API
class ScanConfiguration(BaseModel):
    """Configuration for SCA scan"""
    package_managers: List[str] = Field(
        default=["npm", "pip", "maven", "gradle", "composer", "go"],
        description="Package managers to scan"
    )
    include_dev_dependencies: bool = Field(default=True, description="Include development dependencies")
    include_transitive: bool = Field(default=True, description="Include transitive dependencies")
    vulnerability_threshold: str = Field(default="low", description="Minimum vulnerability severity to report")
    license_policy: Dict[str, Any] = Field(default_factory=dict, description="License compliance policy")
    exclude_paths: List[str] = Field(default_factory=list, description="Paths to exclude from scan")
    max_depth: int = Field(default=10, ge=1, le=50, description="Maximum dependency depth to analyze")

    class Config:
        schema_extra = {
            "example": {
                "package_managers": ["npm", "pip", "maven"],
                "include_dev_dependencies": True,
                "include_transitive": True,
                "vulnerability_threshold": "medium",
                "license_policy": {
                    "allowed_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause"],
                    "forbidden_licenses": ["GPL-3.0", "AGPL-3.0"],
                    "require_attribution": True
                },
                "exclude_paths": ["node_modules", "test", "docs"],
                "max_depth": 10
            }
        }

class ScanRequest(BaseModel):
    """Request model for SCA scan operations"""
    project_path: str = Field(..., description="Path to project directory to scan")
    project_name: str = Field(..., description="Name of the project")
    configuration: ScanConfiguration = Field(default_factory=ScanConfiguration, description="Scan configuration")
    generate_sbom: bool = Field(default=True, description="Generate Software Bill of Materials")
    include_remediation: bool = Field(default=True, description="Include remediation recommendations")

class ScanResponse(BaseModel):
    """Response model for SCA scan operations"""
    scan_id: str
    status: str
    message: str
    summary: Optional[Dict[str, Any]] = None
    execution_time: float = 0.0

class ScanStatusResponse(BaseModel):
    """SCA scan status response"""
    scan_id: str
    status: str
    progress: Dict[str, Any]
    results_available: bool

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime
    version: str

# Global storage for SCA scan sessions
sca_sessions: Dict[str, Dict[str, Any]] = {}

@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Software Composition Analysis Agent",
        "version": "1.0.0",
        "status": "active",
        "endpoints": {
            "scan": "POST /scan - Execute SCA scan",
            "health": "GET /health - Health check",
            "status": "GET /status/{scan_id} - Get scan status",
            "report": "GET /report/{scan_id} - Get detailed report",
            "sbom": "GET /sbom/{scan_id} - Get SBOM",
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

@app.post("/scan", response_model=ScanResponse)
async def execute_sca_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Execute comprehensive SCA scan

    This endpoint performs intelligent software composition analysis including:
    - Multi-package manager dependency discovery (npm, pip, maven, gradle, etc.)
    - Real-time vulnerability detection and CVE matching
    - License compliance assessment and risk analysis
    - Transitive dependency analysis and risk propagation
    - SBOM generation in industry-standard formats
    - AI-powered remediation recommendations
    """
    try:
        # Validate project path
        if not request.project_path:
            raise HTTPException(
                status_code=400,
                detail="Project path is required"
            )

        # Create SCA agent
        agent = SCAAgent()
        scan_id = agent.session_id

        # Store session info
        sca_sessions[scan_id] = {
            "status": "running",
            "start_time": datetime.now(),
            "request": request.dict(),
            "agent": agent
        }

        logger.info(f"Starting SCA scan session {scan_id} for project: {request.project_name}")

        try:
            # Execute SCA scan
            report = await agent.scan_project(
                request.project_path,
                request.configuration.dict()
            )

            # Update session with results
            sca_sessions[scan_id].update({
                "status": "completed",
                "end_time": datetime.now(),
                "report": report
            })

            # Get scan summary
            summary = agent.get_scan_summary(report)

            response = ScanResponse(
                scan_id=scan_id,
                status="completed",
                message=f"SCA scan completed successfully. Found {report.total_vulnerabilities} vulnerabilities in {report.total_components} components.",
                summary=summary,
                execution_time=report.execution_time
            )

            return response

        except Exception as e:
            # Update session with error
            sca_sessions[scan_id].update({
                "status": "error",
                "end_time": datetime.now(),
                "error": str(e)
            })

            logger.error(f"SCA scan session {scan_id} failed: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"SCA scan operation failed: {str(e)}"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in SCA scan endpoint: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/status/{scan_id}", response_model=ScanStatusResponse)
async def get_sca_scan_status(scan_id: str):
    """
    Get status of an SCA scan session

    Returns the current status and progress of an SCA scan operation.
    """
    if scan_id not in sca_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"SCA scan session {scan_id} not found"
        )

    session = sca_sessions[scan_id]

    progress = {
        "start_time": session["start_time"].isoformat(),
        "status": session["status"]
    }

    if "end_time" in session:
        progress["end_time"] = session["end_time"].isoformat()
        progress["duration"] = (session["end_time"] - session["start_time"]).total_seconds()

    if "error" in session:
        progress["error"] = session["error"]

    if "report" in session:
        report = session["report"]
        progress.update({
            "components_analyzed": report.total_components,
            "vulnerabilities_found": report.total_vulnerabilities,
            "critical_vulnerabilities": report.critical_count,
            "high_vulnerabilities": report.high_count,
            "vulnerable_components": report.vulnerable_components
        })

    return ScanStatusResponse(
        scan_id=scan_id,
        status=session["status"],
        progress=progress,
        results_available="report" in session
    )

@app.get("/report/{scan_id}", response_model=Dict[str, Any])
async def get_detailed_sca_report(scan_id: str):
    """
    Get detailed SCA scan report for a session

    Returns comprehensive SCA report including all components, vulnerabilities,
    license analysis, and remediation recommendations.
    """
    if scan_id not in sca_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"SCA scan session {scan_id} not found"
        )

    session = sca_sessions[scan_id]

    if "report" not in session:
        raise HTTPException(
            status_code=404,
            detail=f"No SCA report available for session {scan_id}"
        )

    report = session["report"]

    # Convert report to detailed dictionary
    detailed_report = {
        "scan_info": {
            "scan_id": report.scan_id,
            "target_path": report.target_path,
            "project_name": session["request"]["project_name"],
            "scan_date": report.scan_date.isoformat(),
            "execution_time": report.execution_time,
            "status": report.scan_status.value
        },
        "summary": {
            "total_components": report.total_components,
            "vulnerable_components": report.vulnerable_components,
            "total_vulnerabilities": report.total_vulnerabilities,
            "vulnerability_breakdown": {
                "critical": report.critical_count,
                "high": report.high_count,
                "medium": report.medium_count,
                "low": report.low_count
            }
        },
        "components": [
            {
                "component": {
                    "name": analysis.component.name,
                    "version": analysis.component.version,
                    "type": analysis.component.component_type.value,
                    "package_manager": analysis.component.package_manager,
                    "namespace": analysis.component.namespace,
                    "description": analysis.component.description,
                    "homepage": analysis.component.homepage,
                    "repository": analysis.component.repository,
                    "is_direct_dependency": analysis.component.is_direct_dependency,
                    "depth_level": analysis.component.depth_level
                },
                "analysis": {
                    "risk_score": analysis.risk_score,
                    "vulnerability_count": analysis.vulnerability_count,
                    "critical_vulnerabilities": analysis.critical_vulnerabilities,
                    "high_vulnerabilities": analysis.high_vulnerabilities,
                    "license_risk": analysis.license_risk.value,
                    "outdated": analysis.outdated,
                    "latest_version": analysis.latest_version,
                    "version_lag": analysis.version_lag,
                    "remediation_available": analysis.remediation_available,
                    "recommended_version": analysis.recommended_version,
                    "security_advisories": analysis.security_advisories,
                    "usage_analysis": analysis.usage_analysis
                },
                "vulnerabilities": [
                    {
                        "cve_id": vuln.cve_id,
                        "title": vuln.title,
                        "description": vuln.description,
                        "severity": vuln.severity.value,
                        "cvss_score": vuln.cvss_score,
                        "cvss_vector": vuln.cvss_vector,
                        "published_date": vuln.published_date.isoformat(),
                        "affected_versions": vuln.affected_versions,
                        "fixed_versions": vuln.fixed_versions,
                        "references": vuln.references,
                        "exploit_available": vuln.exploit_available
                    }
                    for vuln in analysis.component.vulnerabilities
                ],
                "license": {
                    "name": analysis.component.license.name,
                    "spdx_id": analysis.component.license.spdx_id,
                    "risk_level": analysis.component.license.risk_level.value,
                    "commercial_use": analysis.component.license.commercial_use,
                    "modification_allowed": analysis.component.license.modification_allowed,
                    "distribution_allowed": analysis.component.license.distribution_allowed,
                    "copyleft": analysis.component.license.copyleft,
                    "attribution_required": analysis.component.license.attribution_required,
                    "restrictions": analysis.component.license.restrictions,
                    "obligations": analysis.component.license.obligations
                } if analysis.component.license else None
            }
            for analysis in report.components
        ],
        "risk_analysis": report.risk_summary,
        "remediation_recommendations": report.remediation_recommendations,
        "error_messages": report.error_messages
    }

    return detailed_report

@app.get("/sbom/{scan_id}", response_model=Dict[str, Any])
async def get_sbom(scan_id: str, format: str = "cyclonedx"):
    """
    Get Software Bill of Materials (SBOM) for a scan

    Returns SBOM in requested format (cyclonedx, spdx, or custom).
    """
    if scan_id not in sca_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"SCA scan session {scan_id} not found"
        )

    session = sca_sessions[scan_id]

    if "report" not in session:
        raise HTTPException(
            status_code=404,
            detail=f"No SCA report available for session {scan_id}"
        )

    report = session["report"]

    if format.lower() not in ["cyclonedx", "spdx", "custom"]:
        raise HTTPException(
            status_code=400,
            detail="Supported formats: cyclonedx, spdx, custom"
        )

    if format.lower() == "cyclonedx":
        return report.sbom
    elif format.lower() == "spdx":
        # Convert to SPDX format
        return await _convert_to_spdx(report.sbom)
    else:
        # Custom format
        return await _convert_to_custom_format(report.sbom)

async def _convert_to_spdx(cyclonedx_sbom: Dict[str, Any]) -> Dict[str, Any]:
    """Convert CycloneDX SBOM to SPDX format"""
    spdx_sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "SCA Scan Results",
        "documentNamespace": f"https://sca-agent.example.com/{cyclonedx_sbom.get('serialNumber', 'unknown')}",
        "creationInfo": {
            "created": cyclonedx_sbom.get("metadata", {}).get("timestamp", datetime.now().isoformat()),
            "creators": ["Tool: SCA Agent v1.0.0"]
        },
        "packages": []
    }

    for component in cyclonedx_sbom.get("components", []):
        package = {
            "SPDXID": f"SPDXRef-{component['name'].replace('/', '-')}",
            "name": component["name"],
            "versionInfo": component["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "copyrightText": "NOASSERTION"
        }

        if "licenses" in component:
            package["licenseConcluded"] = component["licenses"][0]["license"]["id"]

        spdx_sbom["packages"].append(package)

    return spdx_sbom

async def _convert_to_custom_format(cyclonedx_sbom: Dict[str, Any]) -> Dict[str, Any]:
    """Convert to custom simplified format"""
    custom_sbom = {
        "format": "custom",
        "version": "1.0",
        "generated": datetime.now().isoformat(),
        "components": []
    }

    for component in cyclonedx_sbom.get("components", []):
        custom_component = {
            "name": component["name"],
            "version": component["version"],
            "type": component["type"],
            "package_url": component.get("purl", ""),
            "license": component.get("licenses", [{}])[0].get("license", {}).get("id", "unknown"),
            "vulnerabilities": len(component.get("vulnerabilities", [])),
            "critical_vulns": sum(1 for v in component.get("vulnerabilities", [])
                                if v.get("ratings", [{}])[0].get("severity", "").lower() == "critical")
        }
        custom_sbom["components"].append(custom_component)

    return custom_sbom

@app.get("/sessions", response_model=Dict[str, Any])
async def list_sca_sessions():
    """
    List all SCA scan sessions

    Returns a summary of all SCA scan sessions with their status.
    """
    sessions_summary = {}

    for scan_id, session_data in sca_sessions.items():
        summary = {
            "status": session_data["status"],
            "start_time": session_data["start_time"].isoformat(),
            "project_name": session_data["request"]["project_name"],
            "project_path": session_data["request"]["project_path"]
        }

        if "end_time" in session_data:
            summary["end_time"] = session_data["end_time"].isoformat()

        if "report" in session_data:
            report = session_data["report"]
            summary.update({
                "total_components": report.total_components,
                "total_vulnerabilities": report.total_vulnerabilities,
                "critical_vulnerabilities": report.critical_count,
                "execution_time": report.execution_time
            })

        sessions_summary[scan_id] = summary

    return {
        "total_sessions": len(sessions_summary),
        "sessions": sessions_summary
    }

@app.delete("/sessions/{scan_id}")
async def delete_sca_session(scan_id: str):
    """
    Delete an SCA scan session

    Removes an SCA scan session and its associated data.
    """
    if scan_id not in sca_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"SCA scan session {scan_id} not found"
        )

    del sca_sessions[scan_id]

    return {
        "message": f"SCA scan session {scan_id} deleted successfully"
    }

@app.get("/package-managers", response_model=Dict[str, Any])
async def list_supported_package_managers():
    """
    List supported package managers

    Returns information about all supported package managers and their capabilities.
    """
    # Get package manager information from agent
    agent = SCAAgent()
    package_managers = {}

    for pm_name, pm_config in agent.package_managers.items():
        package_managers[pm_name] = {
            "name": pm_name.upper(),
            "manifest_files": pm_config["manifest_files"],
            "lock_files": pm_config["lock_files"],
            "registry_url": pm_config["registry_url"],
            "supported": True
        }

    return {
        "supported_package_managers": list(package_managers.keys()),
        "package_managers": package_managers,
        "total_supported": len(package_managers)
    }

@app.get("/vulnerabilities/{component_name}")
async def get_component_vulnerabilities(component_name: str, version: Optional[str] = None):
    """
    Get known vulnerabilities for a specific component

    Returns vulnerability information for the specified component and version.
    """
    agent = SCAAgent()

    # Look up vulnerabilities in the knowledge base
    known_vulns = agent.vulnerability_db["known_vulnerabilities"].get(component_name, [])

    if not known_vulns:
        return {
            "component": component_name,
            "version": version,
            "vulnerabilities": [],
            "message": "No known vulnerabilities found"
        }

    vulnerabilities = []
    for vuln in known_vulns:
        # If version is specified, check if it's affected
        if version and not agent._is_version_affected(version, vuln["affected_versions"]):
            continue

        vulnerabilities.append({
            "cve_id": vuln["cve_id"],
            "title": vuln["title"],
            "severity": vuln["severity"].value,
            "cvss_score": vuln["cvss_score"],
            "affected_versions": vuln["affected_versions"],
            "fixed_versions": vuln["fixed_versions"]
        })

    return {
        "component": component_name,
        "version": version,
        "vulnerabilities": vulnerabilities,
        "total_vulnerabilities": len(vulnerabilities)
    }

@app.get("/licenses", response_model=Dict[str, Any])
async def list_license_information():
    """
    List license information and risk assessments

    Returns information about supported licenses and their risk classifications.
    """
    agent = SCAAgent()
    licenses = {}

    for license_id, license_info in agent.license_db.items():
        licenses[license_id] = {
            "name": license_info.name,
            "spdx_id": license_info.spdx_id,
            "risk_level": license_info.risk_level.value,
            "commercial_use": license_info.commercial_use,
            "modification_allowed": license_info.modification_allowed,
            "distribution_allowed": license_info.distribution_allowed,
            "copyleft": license_info.copyleft,
            "attribution_required": license_info.attribution_required,
            "restrictions": license_info.restrictions,
            "obligations": license_info.obligations
        }

    return {
        "supported_licenses": list(licenses.keys()),
        "licenses": licenses,
        "risk_categories": {
            "approved": "Low risk, suitable for commercial use",
            "low_risk": "Generally acceptable with minor considerations",
            "medium_risk": "Requires legal review and compliance measures",
            "high_risk": "Significant restrictions, careful evaluation needed",
            "unknown": "License not recognized, manual review required"
        }
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
    logger.info("Software Composition Analysis Agent API starting up...")
    logger.info("Available endpoints:")
    logger.info("  POST /scan - Execute SCA scan")
    logger.info("  GET /health - Health check")
    logger.info("  GET /status/{scan_id} - Get scan status")
    logger.info("  GET /report/{scan_id} - Get detailed report")
    logger.info("  GET /sbom/{scan_id} - Get SBOM")
    logger.info("  GET /package-managers - List supported package managers")
    logger.info("  GET /docs - API documentation")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event handler"""
    logger.info("Software Composition Analysis Agent API shutting down...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)