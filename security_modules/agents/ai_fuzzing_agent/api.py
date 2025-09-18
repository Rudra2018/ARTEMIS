"""
FastAPI REST API for AI Fuzzing Agent

Provides RESTful endpoints for intelligent fuzzing operations including
semantic fuzzing, payload mutation, and vulnerability detection.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
import asyncio
import logging
from datetime import datetime

from .fuzzing_agent import AIFuzzingAgent, FuzzingStrategy, FuzzingConfig, FuzzingReport

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="AI Fuzzing Agent",
    description="Intelligent input mutation and fuzzing for LLM interfaces using semantic fuzzing, payload mutation, and coverage metrics",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Pydantic models for API
class FuzzingRequest(BaseModel):
    """Request model for fuzzing operations"""
    target_url: str = Field(..., description="Target URL to fuzz")
    input_schema: Dict[str, str] = Field(
        default={"input": "string"},
        description="Input schema defining field types"
    )
    strategy: FuzzingStrategy = Field(
        default=FuzzingStrategy.SEMANTIC,
        description="Fuzzing strategy to use"
    )
    base_input: str = Field(
        default="test input",
        description="Base input to mutate"
    )
    max_iterations: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Maximum number of fuzzing iterations"
    )
    timeout: float = Field(
        default=30.0,
        ge=1.0,
        le=300.0,
        description="Request timeout in seconds"
    )
    parallel_requests: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Number of parallel requests"
    )

    class Config:
        schema_extra = {
            "example": {
                "target_url": "https://example.com/chat",
                "input_schema": {"input": "string", "context": "string"},
                "strategy": "semantic",
                "base_input": "Hello, how can you help me?",
                "max_iterations": 50,
                "timeout": 30.0,
                "parallel_requests": 5
            }
        }

class FuzzingResponse(BaseModel):
    """Response model for fuzzing operations"""
    session_id: str
    status: str
    message: str
    report: Optional[Dict[str, Any]] = None
    vulnerabilities_found: int = 0
    execution_time: float = 0.0

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime
    version: str

class FuzzingStatusResponse(BaseModel):
    """Fuzzing status response"""
    session_id: str
    status: str
    progress: Dict[str, Any]
    results_available: bool

# Global storage for fuzzing sessions (in production, use Redis or database)
fuzzing_sessions: Dict[str, Dict[str, Any]] = {}

@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with API information"""
    return {
        "service": "AI Fuzzing Agent",
        "version": "1.0.0",
        "status": "active",
        "endpoints": {
            "fuzz": "POST /fuzz - Execute fuzzing operation",
            "health": "GET /health - Health check",
            "status": "GET /status/{session_id} - Get fuzzing status",
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

@app.post("/fuzz", response_model=FuzzingResponse)
async def fuzz_endpoint(request: FuzzingRequest, background_tasks: BackgroundTasks):
    """
    Execute fuzzing operation against target URL

    This endpoint performs intelligent fuzzing using various strategies including:
    - Semantic mutations using transformer models
    - Random payload generation
    - Boundary testing
    - Adversarial payload injection
    - Vulnerability detection and analysis
    """
    try:
        # Validate target URL
        if not request.target_url.startswith(('http://', 'https://')):
            raise HTTPException(
                status_code=400,
                detail="Target URL must start with http:// or https://"
            )

        # Create fuzzing configuration
        config = FuzzingConfig(
            strategy=request.strategy,
            max_iterations=request.max_iterations,
            timeout=request.timeout,
            parallel_requests=request.parallel_requests
        )

        # Create fuzzing agent
        agent = AIFuzzingAgent(config)
        session_id = agent.session_id

        # Store session info
        fuzzing_sessions[session_id] = {
            "status": "running",
            "start_time": datetime.now(),
            "request": request.dict(),
            "agent": agent
        }

        logger.info(f"Starting fuzzing session {session_id} for {request.target_url}")

        # Execute fuzzing (this will be async)
        try:
            report = await agent.fuzz_target(
                request.target_url,
                request.input_schema,
                request.base_input
            )

            # Update session with results
            fuzzing_sessions[session_id].update({
                "status": "completed",
                "end_time": datetime.now(),
                "report": report
            })

            # Prepare response
            response = FuzzingResponse(
                session_id=session_id,
                status="completed",
                message=f"Fuzzing completed successfully. Found {report.vulnerabilities_found} vulnerabilities.",
                report={
                    "session_id": report.session_id,
                    "target_url": report.target_url,
                    "strategy": report.strategy.value,
                    "total_payloads": report.total_payloads,
                    "successful_tests": report.successful_tests,
                    "vulnerabilities_found": report.vulnerabilities_found,
                    "coverage_score": report.coverage_score,
                    "execution_time": report.execution_time,
                    "vulnerability_summary": report.vulnerability_summary,
                    "recommendations": report.recommendations,
                    "created_at": report.created_at.isoformat(),
                    "results": [
                        {
                            "payload_id": r.payload_id,
                            "payload": r.payload[:100] + "..." if len(r.payload) > 100 else r.payload,
                            "status_code": r.status_code,
                            "response_time": r.response_time,
                            "vulnerability_detected": r.vulnerability_detected,
                            "vulnerability_type": r.vulnerability_type,
                            "confidence": r.confidence,
                            "error": r.error
                        }
                        for r in report.results[:50]  # Limit to first 50 results for API response
                    ]
                },
                vulnerabilities_found=report.vulnerabilities_found,
                execution_time=report.execution_time
            )

            return response

        except Exception as e:
            # Update session with error
            fuzzing_sessions[session_id].update({
                "status": "error",
                "end_time": datetime.now(),
                "error": str(e)
            })

            logger.error(f"Fuzzing session {session_id} failed: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Fuzzing operation failed: {str(e)}"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in fuzzing endpoint: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/status/{session_id}", response_model=FuzzingStatusResponse)
async def get_fuzzing_status(session_id: str):
    """
    Get status of a fuzzing session

    Returns the current status and progress of a fuzzing operation.
    """
    if session_id not in fuzzing_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Fuzzing session {session_id} not found"
        )

    session = fuzzing_sessions[session_id]

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
            "total_payloads": report.total_payloads,
            "vulnerabilities_found": report.vulnerabilities_found,
            "coverage_score": report.coverage_score
        })

    return FuzzingStatusResponse(
        session_id=session_id,
        status=session["status"],
        progress=progress,
        results_available="report" in session
    )

@app.get("/sessions", response_model=Dict[str, Any])
async def list_fuzzing_sessions():
    """
    List all fuzzing sessions

    Returns a summary of all fuzzing sessions with their status.
    """
    sessions_summary = {}

    for session_id, session_data in fuzzing_sessions.items():
        summary = {
            "status": session_data["status"],
            "start_time": session_data["start_time"].isoformat(),
            "target_url": session_data["request"]["target_url"],
            "strategy": session_data["request"]["strategy"]
        }

        if "end_time" in session_data:
            summary["end_time"] = session_data["end_time"].isoformat()

        if "report" in session_data:
            report = session_data["report"]
            summary.update({
                "vulnerabilities_found": report.vulnerabilities_found,
                "total_payloads": report.total_payloads,
                "execution_time": report.execution_time
            })

        sessions_summary[session_id] = summary

    return {
        "total_sessions": len(sessions_summary),
        "sessions": sessions_summary
    }

@app.delete("/sessions/{session_id}")
async def delete_fuzzing_session(session_id: str):
    """
    Delete a fuzzing session

    Removes a fuzzing session and its associated data.
    """
    if session_id not in fuzzing_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Fuzzing session {session_id} not found"
        )

    del fuzzing_sessions[session_id]

    return {
        "message": f"Fuzzing session {session_id} deleted successfully"
    }

@app.get("/strategies", response_model=Dict[str, Any])
async def list_fuzzing_strategies():
    """
    List available fuzzing strategies

    Returns all available fuzzing strategies with descriptions.
    """
    strategies = {
        "semantic": {
            "name": "Semantic Fuzzing",
            "description": "Uses transformer models to generate semantically meaningful mutations"
        },
        "random": {
            "name": "Random Fuzzing",
            "description": "Generates random payloads with various character sets"
        },
        "mutation": {
            "name": "Mutation-Based Fuzzing",
            "description": "Applies systematic mutations to base inputs"
        },
        "grammar_based": {
            "name": "Grammar-Based Fuzzing",
            "description": "Uses predefined grammars to generate structured inputs"
        },
        "adversarial": {
            "name": "Adversarial Fuzzing",
            "description": "Uses known attack patterns and vulnerability templates"
        },
        "boundary": {
            "name": "Boundary Testing",
            "description": "Tests edge cases and boundary conditions"
        },
        "coverage_guided": {
            "name": "Coverage-Guided Fuzzing",
            "description": "Optimizes for maximum code coverage during fuzzing"
        }
    }

    return {
        "available_strategies": list(strategies.keys()),
        "strategies": strategies
    }

@app.get("/report/{session_id}", response_model=Dict[str, Any])
async def get_detailed_report(session_id: str):
    """
    Get detailed fuzzing report for a session

    Returns complete fuzzing report including all test results and analysis.
    """
    if session_id not in fuzzing_sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Fuzzing session {session_id} not found"
        )

    session = fuzzing_sessions[session_id]

    if "report" not in session:
        raise HTTPException(
            status_code=404,
            detail=f"No report available for session {session_id}"
        )

    report = session["report"]

    # Convert report to dictionary with full details
    detailed_report = {
        "session_id": report.session_id,
        "target_url": report.target_url,
        "strategy": report.strategy.value,
        "total_payloads": report.total_payloads,
        "successful_tests": report.successful_tests,
        "vulnerabilities_found": report.vulnerabilities_found,
        "coverage_score": report.coverage_score,
        "execution_time": report.execution_time,
        "vulnerability_summary": report.vulnerability_summary,
        "recommendations": report.recommendations,
        "created_at": report.created_at.isoformat(),
        "results": [
            {
                "payload_id": r.payload_id,
                "payload": r.payload,
                "response": r.response,
                "status_code": r.status_code,
                "response_time": r.response_time,
                "vulnerability_detected": r.vulnerability_detected,
                "vulnerability_type": r.vulnerability_type,
                "confidence": r.confidence,
                "error": r.error,
                "timestamp": r.timestamp.isoformat()
            }
            for r in report.results
        ]
    }

    return detailed_report

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
    logger.info("AI Fuzzing Agent API starting up...")
    logger.info("Available endpoints:")
    logger.info("  POST /fuzz - Execute fuzzing operation")
    logger.info("  GET /health - Health check")
    logger.info("  GET /status/{session_id} - Get fuzzing status")
    logger.info("  GET /sessions - List all sessions")
    logger.info("  GET /strategies - List fuzzing strategies")
    logger.info("  GET /docs - API documentation")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown event handler"""
    logger.info("AI Fuzzing Agent API shutting down...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)