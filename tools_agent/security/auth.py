import os
from langgraph_sdk import Auth
from langgraph_sdk.auth.types import StudioUser
from typing import Optional, Any
import httpx
from typing import Dict

# Initialize Clerk API key from environment variable
clerk_api_key = os.environ.get("CLERK_SECRET_KEY")
clerk_api_base = "https://api.clerk.dev/v1"

if not clerk_api_key:
    raise ValueError("CLERK_SECRET_KEY environment variable is required")

auth = Auth()

async def verify_clerk_token(token: str) -> Dict[str, Any]:
    """Verify a Clerk session token and return user data."""
    async with httpx.AsyncClient() as client:
        headers = {
            "Authorization": f"Bearer {clerk_api_key}",
            "Content-Type": "application/json"
        }
        
        response = await client.get(
            f"{clerk_api_base}/sessions/{token}",
            headers=headers
        )
        
        if response.status_code != 200:
            raise ValueError("Invalid token")
            
        session_data = response.json()
        return session_data

@auth.authenticate
async def get_current_user(authorization: str | None) -> Auth.types.MinimalUserDict:
    """Check if the user's JWT token is valid using Clerk."""

    # Ensure we have authorization header
    if not authorization:
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Authorization header missing"
        )

    # Parse the authorization header
    try:
        scheme, token = authorization.split()
        assert scheme.lower() == "bearer"
    except (ValueError, AssertionError):
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Invalid authorization header format"
        )

    try:
        # Verify the token with Clerk
        session_data = await verify_clerk_token(token)
        user_id = session_data["user_id"]

        if not user_id:
            raise Auth.exceptions.HTTPException(
                status_code=401, detail="Invalid token or user not found"
            )

        # Return user info if valid
        return {
            "identity": user_id,
        }
    except Exception as e:
        # Handle any errors from Clerk
        raise Auth.exceptions.HTTPException(
            status_code=401, detail=f"Authentication error: {str(e)}"
        )

@auth.on.threads.create
@auth.on.threads.create_run
async def on_thread_create(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.threads.create.value,
):
    """Add owner when creating threads.

    This handler runs when creating new threads and does two things:
    1. Sets metadata on the thread being created to track ownership
    2. Returns a filter that ensures only the creator can access it
    """

    if isinstance(ctx.user, StudioUser):
        return

    # Add owner metadata to the thread being created
    # This metadata is stored with the thread and persists
    metadata = value.setdefault("metadata", {})
    metadata["owner"] = ctx.user.identity


@auth.on.threads.read
@auth.on.threads.delete
@auth.on.threads.update
@auth.on.threads.search
async def on_thread_read(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.threads.read.value,
):
    """Only let users read their own threads.

    This handler runs on read operations. We don't need to set
    metadata since the thread already exists - we just need to
    return a filter to ensure users can only see their own threads.
    """
    if isinstance(ctx.user, StudioUser):
        return

    return {"owner": ctx.user.identity}


@auth.on.assistants.create
async def on_assistants_create(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.assistants.create.value,
):
    if isinstance(ctx.user, StudioUser):
        return

    # Add owner metadata to the assistant being created
    # This metadata is stored with the assistant and persists
    metadata = value.setdefault("metadata", {})
    metadata["owner"] = ctx.user.identity


@auth.on.assistants.read
@auth.on.assistants.delete
@auth.on.assistants.update
@auth.on.assistants.search
async def on_assistants_read(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.assistants.read.value,
):
    """Only let users read their own assistants.

    This handler runs on read operations. We don't need to set
    metadata since the assistant already exists - we just need to
    return a filter to ensure users can only see their own assistants.
    """

    if isinstance(ctx.user, StudioUser):
        return

    return {"owner": ctx.user.identity}


@auth.on.store()
async def authorize_store(ctx: Auth.types.AuthContext, value: dict):
    if isinstance(ctx.user, StudioUser):
        return

    # The "namespace" field for each store item is a tuple you can think of as the directory of an item.
    namespace: tuple = value["namespace"]
    assert namespace[0] == ctx.user.identity, "Not authorized"
