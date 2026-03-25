"""Agent management and A2A control-plane APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from gateway.api.auth import require_admin_auth
from gateway.services.agent_registry import agent_registry


agent_control_router = APIRouter(
    prefix="/admin",
    tags=["agent-control"],
    dependencies=[Depends(require_admin_auth)],
)


class AgentUpsertRequest(BaseModel):
    """Create or wrap a managed agent."""

    agent_id: Optional[str] = None
    display_name: str = Field(..., min_length=1)
    agent_type: str = Field(..., min_length=1)
    status: str = "ACTIVE"
    wrapped: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)
    changed_by: str = "admin"


class AgentRecord(BaseModel):
    """Managed agent record."""

    agent_id: str
    display_name: str
    agent_type: str
    status: str
    wrapped: bool
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None


class AgentResponse(BaseModel):
    """Single agent response."""

    success: bool
    message: str
    agent: AgentRecord


class AgentListResponse(BaseModel):
    """List of managed agents."""

    success: bool
    total: int
    limit: int
    offset: int
    agents: List[AgentRecord]


class AgentLinkRequest(BaseModel):
    """Upsert A2A link between agents."""

    source_agent_id: str = Field(..., min_length=1)
    target_agent_id: str = Field(..., min_length=1)
    protocol: str = "A2A"
    status: str = "ACTIVE"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    changed_by: str = "admin"


class AgentLinkRecord(BaseModel):
    """A2A link record."""

    source_agent_id: str
    target_agent_id: str
    protocol: str
    status: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None


class AgentLinkResponse(BaseModel):
    """Single A2A link response."""

    success: bool
    message: str
    link: AgentLinkRecord


class AgentLinkListResponse(BaseModel):
    """List A2A links response."""

    success: bool
    total: int
    limit: int
    offset: int
    links: List[AgentLinkRecord]


class A2AInteractionCreateRequest(BaseModel):
    """Create interaction request."""

    source_agent_id: str = Field(..., min_length=1)
    target_agent_id: str = Field(..., min_length=1)
    payload: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_by: str = "admin"


class A2AInteractionReviewRequest(BaseModel):
    """Review interaction (approve/block)."""

    reviewed_by: str = "admin"
    reason: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class A2AInteractionRecord(BaseModel):
    """A2A interaction record."""

    interaction_id: str
    source_agent_id: str
    target_agent_id: str
    review_status: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    decision_reason: Optional[str] = None
    reviewed_by: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class A2AInteractionResponse(BaseModel):
    """Single interaction response."""

    success: bool
    message: str
    interaction: A2AInteractionRecord


class A2AInteractionListResponse(BaseModel):
    """List interaction response."""

    success: bool
    total: int
    limit: int
    offset: int
    interactions: List[A2AInteractionRecord]


@agent_control_router.post("/agents/create", response_model=AgentResponse)
async def create_agent(request: AgentUpsertRequest) -> AgentResponse:
    """Create a managed agent."""
    try:
        record = await agent_registry.create_or_wrap_agent(
            agent_id=request.agent_id,
            display_name=request.display_name,
            agent_type=request.agent_type,
            wrapped=request.wrapped,
            status=request.status,
            metadata=request.metadata,
            changed_by=request.changed_by,
        )
        return AgentResponse(
            success=True,
            message=f"Agent '{record['agent_id']}' created/updated",
            agent=AgentRecord(**record),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@agent_control_router.post("/agents/wrap", response_model=AgentResponse)
async def wrap_agent(request: AgentUpsertRequest) -> AgentResponse:
    """Wrap an existing external agent for controlled governance."""
    try:
        record = await agent_registry.create_or_wrap_agent(
            agent_id=request.agent_id,
            display_name=request.display_name,
            agent_type=request.agent_type,
            wrapped=True,
            status=request.status,
            metadata=request.metadata,
            changed_by=request.changed_by,
        )
        return AgentResponse(
            success=True,
            message=f"Agent '{record['agent_id']}' wrapped/updated",
            agent=AgentRecord(**record),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@agent_control_router.get("/agents", response_model=AgentListResponse)
async def list_agents(
    limit: int = 100,
    offset: int = 0,
    status_filter: Optional[str] = None,
) -> AgentListResponse:
    """List managed agents."""
    try:
        records = await agent_registry.list_agents(
            limit=limit,
            offset=offset,
            status=status_filter,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return AgentListResponse(
        success=True,
        total=len(records),
        limit=limit,
        offset=offset,
        agents=[AgentRecord(**item) for item in records],
    )


@agent_control_router.get("/agents/links", response_model=AgentLinkListResponse)
async def list_agent_links(
    limit: int = 100,
    offset: int = 0,
    source_agent_id: Optional[str] = None,
    target_agent_id: Optional[str] = None,
) -> AgentLinkListResponse:
    """List A2A links between agents."""
    records = await agent_registry.list_links(
        limit=limit,
        offset=offset,
        source_agent_id=source_agent_id,
        target_agent_id=target_agent_id,
    )
    return AgentLinkListResponse(
        success=True,
        total=len(records),
        limit=limit,
        offset=offset,
        links=[AgentLinkRecord(**item) for item in records],
    )


@agent_control_router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: str) -> AgentResponse:
    """Get a managed agent by id."""
    record = await agent_registry.get_agent(agent_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found",
        )
    return AgentResponse(
        success=True,
        message=f"Agent '{agent_id}'",
        agent=AgentRecord(**record),
    )


@agent_control_router.post("/agents/link", response_model=AgentLinkResponse)
async def upsert_agent_link(request: AgentLinkRequest) -> AgentLinkResponse:
    """Create/update A2A link between two agents."""
    try:
        record = await agent_registry.upsert_link(
            source_agent_id=request.source_agent_id,
            target_agent_id=request.target_agent_id,
            protocol=request.protocol,
            status=request.status,
            metadata=request.metadata,
            changed_by=request.changed_by,
        )
        return AgentLinkResponse(
            success=True,
            message=(
                f"A2A link '{record['source_agent_id']}' -> "
                f"'{record['target_agent_id']}' ({record['protocol']}) upserted"
            ),
            link=AgentLinkRecord(**record),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@agent_control_router.post("/a2a/interactions", response_model=A2AInteractionResponse)
async def create_a2a_interaction(
    request: A2AInteractionCreateRequest,
) -> A2AInteractionResponse:
    """Create A2A interaction request entry."""
    try:
        record = await agent_registry.create_interaction(
            source_agent_id=request.source_agent_id,
            target_agent_id=request.target_agent_id,
            payload=request.payload,
            metadata=request.metadata,
            created_by=request.created_by,
        )
        return A2AInteractionResponse(
            success=True,
            message=f"A2A interaction '{record['interaction_id']}' created",
            interaction=A2AInteractionRecord(**record),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@agent_control_router.get("/a2a/interactions", response_model=A2AInteractionListResponse)
async def list_a2a_interactions(
    limit: int = 100,
    offset: int = 0,
    source_agent_id: Optional[str] = None,
    target_agent_id: Optional[str] = None,
    review_status: Optional[str] = None,
) -> A2AInteractionListResponse:
    """List A2A interaction records."""
    try:
        records = await agent_registry.list_interactions(
            limit=limit,
            offset=offset,
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            review_status=review_status,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return A2AInteractionListResponse(
        success=True,
        total=len(records),
        limit=limit,
        offset=offset,
        interactions=[A2AInteractionRecord(**item) for item in records],
    )


@agent_control_router.get("/a2a/interactions/{interaction_id}", response_model=A2AInteractionResponse)
async def get_a2a_interaction(interaction_id: str) -> A2AInteractionResponse:
    """Get interaction status by interaction id."""
    record = await agent_registry.get_interaction(interaction_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"A2A interaction '{interaction_id}' not found",
        )
    return A2AInteractionResponse(
        success=True,
        message=f"A2A interaction '{interaction_id}'",
        interaction=A2AInteractionRecord(**record),
    )


async def _review_a2a_interaction(
    interaction_id: str,
    review_status: str,
    payload: A2AInteractionReviewRequest,
) -> A2AInteractionResponse:
    """Shared approve/block interaction operation."""
    try:
        record = await agent_registry.review_interaction(
            interaction_id=interaction_id,
            review_status=review_status,
            reviewed_by=payload.reviewed_by,
            reason=payload.reason,
            metadata=payload.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"A2A interaction '{interaction_id}' not found",
        )
    return A2AInteractionResponse(
        success=True,
        message=f"A2A interaction '{interaction_id}' marked as {review_status.upper()}",
        interaction=A2AInteractionRecord(**record),
    )


@agent_control_router.post(
    "/a2a/interactions/{interaction_id}/approve",
    response_model=A2AInteractionResponse,
)
async def approve_a2a_interaction(
    interaction_id: str,
    payload: A2AInteractionReviewRequest,
) -> A2AInteractionResponse:
    """Approve an A2A interaction."""
    return await _review_a2a_interaction(interaction_id, "APPROVED", payload)


@agent_control_router.post(
    "/a2a/interactions/{interaction_id}/block",
    response_model=A2AInteractionResponse,
)
async def block_a2a_interaction(
    interaction_id: str,
    payload: A2AInteractionReviewRequest,
) -> A2AInteractionResponse:
    """Block an A2A interaction."""
    return await _review_a2a_interaction(interaction_id, "BLOCKED", payload)

