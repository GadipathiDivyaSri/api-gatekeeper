"""
DemoShop Backend Application (Module M1).
A small, secure FastAPI REST API that API Gatekeeper protects.
All queries are parameterized and all inputs are validated with Pydantic.
"""

from __future__ import annotations

import html
import secrets
import sqlite3
from contextlib import asynccontextmanager
from typing import Annotated, Generator

from fastapi import Depends, FastAPI, HTTPException, Path as FPath, Query, Request, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from backend.seed import get_db_path, hash_password, seed_database, verify_password


# -----------------------------------------------------------------------------
# Pydantic Models (OpenAPI Documentation)
# -----------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str = Field(..., example="healthy")
    service: str = Field(..., example="DemoShop")
    version: str = Field(..., example="1.0.0")


class ProductResponse(BaseModel):
    id: int = Field(..., example=1)
    name: str = Field(..., example="Smartphone X")
    category: str = Field(..., example="electronics")
    price: float = Field(..., example=799.99)
    stock: int = Field(..., example=45)


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50, description="Username")
    password: str = Field(..., min_length=1, max_length=100, description="Password")


class LoginResponse(BaseModel):
    token: str = Field(..., description="Bearer token")
    token_type: str = Field(default="bearer")
    username: str = Field(..., description="Authenticated username")
    role: str = Field(..., description="User role")


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    username: str = Field(..., min_length=3, max_length=50, description="New username")
    email: str = Field(..., min_length=5, max_length=100, description="Email address")
    password: str = Field(..., min_length=6, max_length=100, description="New password")


class RegisterResponse(BaseModel):
    message: str = Field(..., example="User registered successfully")
    username: str = Field(..., example="newuser")
    email: str = Field(..., example="newuser@demoshop.test")
    role: str = Field(..., example="customer")


class FeedbackRequest(BaseModel):
    product_id: int = Field(..., ge=1, description="Target product ID")
    comment: str = Field(..., min_length=1, max_length=500, description="Feedback comment (max 500 chars)")


class FeedbackResponse(BaseModel):
    id: int = Field(..., description="Created feedback record ID")
    product_id: int = Field(..., description="Associated product ID")
    comment: str = Field(..., description="Escaped feedback comment")
    status: str = Field(default="received")


class OrderItem(BaseModel):
    product_id: int = Field(..., example=1)
    name: str = Field(..., example="Smartphone X")
    quantity: int = Field(..., example=1)
    price: float = Field(..., example=799.99)


class ShippingAddress(BaseModel):
    street: str = Field(..., example="100 Innovation Way")
    city: str = Field(..., example="Cyber City")
    country: str = Field(..., example="IN")
    postal_code: str = Field(..., example="560001")


class OrderResponse(BaseModel):
    order_id: int = Field(..., example=101)
    status: str = Field(..., example="shipped")
    customer: str = Field(..., example="alice@demoshop.test")
    items: list[OrderItem]
    total: float = Field(..., example=999.98)
    shipping_address: ShippingAddress
    tracking_number: str = Field(..., example="TRK-101-98765")


# -----------------------------------------------------------------------------
# Application Setup & Lifespan
# -----------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ensure database is seeded if missing upon application startup."""
    db_path = get_db_path()
    if not db_path.exists():
        seed_database(db_path)
    yield


app = FastAPI(
    title="DemoShop API",
    version="1.0.0",
    description="Secure sample e-commerce API protected by API Gatekeeper.",
    lifespan=lifespan,
)


def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Provide a database connection per request with Row factory."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Middleware: Request Logging (Observes X-Request-ID)
# -----------------------------------------------------------------------------


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log incoming request method, path, and incoming X-Request-ID."""
    x_request_id = request.headers.get("x-request-id", "-")
    print(f"[DEMOSHOP] {request.method} {request.url.path} | X-Request-ID: {x_request_id}", flush=True)
    response = await call_next(request)
    return response


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------


@app.get(
    "/api/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Service health check",
)
def get_health() -> HealthResponse:
    """Return healthy status of the DemoShop service."""
    return HealthResponse(status="healthy", service="DemoShop", version="1.0.0")


@app.get(
    "/api/products",
    response_model=list[ProductResponse],
    tags=["Products"],
    summary="List and search products",
)
def list_products(
    search: Annotated[str | None, Query(description="Search term in product name", max_length=100)] = None,
    category: Annotated[str | None, Query(description="Filter by category", max_length=50)] = None,
    limit: Annotated[int, Query(ge=1, le=50, description="Max products to return")] = 20,
    conn: sqlite3.Connection = Depends(get_db),
) -> list[ProductResponse]:
    """Retrieve catalog products with parameterized LIKE search and category filters."""
    query = "SELECT id, name, category, price, stock FROM products"
    conditions: list[str] = []
    params: list[str | int] = []

    if search:
        conditions.append("name LIKE ?")
        params.append(f"%{search}%")

    if category:
        conditions.append("category = ?")
        params.append(category)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " LIMIT ?"
    params.append(limit)

    cursor = conn.cursor()
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    return [ProductResponse(**dict(row)) for row in rows]


@app.get(
    "/api/products/{product_id}",
    response_model=ProductResponse,
    tags=["Products"],
    summary="Get product details by ID",
)
def get_product(
    product_id: Annotated[int, FPath(ge=1, description="Unique product ID")],
    conn: sqlite3.Connection = Depends(get_db),
) -> ProductResponse:
    """Fetch a single product by its integer ID."""
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, category, price, stock FROM products WHERE id = ?", (product_id,))
    row = cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")
    return ProductResponse(**dict(row))


@app.post(
    "/api/login",
    response_model=LoginResponse,
    tags=["Auth"],
    summary="Authenticate user",
)
def login_user(
    payload: LoginRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> LoginResponse:
    """Authenticate username and password with constant-time hash comparison."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, password_hash, role FROM users WHERE username = ?",
        (payload.username,),
    )
    user = cursor.fetchone()

    # Fixed dummy hash for constant-time comparison against nonexistent users
    dummy_hash = (
        "00000000000000000000000000000000"
        "$0000000000000000000000000000000000000000000000000000000000000000"
    )
    stored_hash = user["password_hash"] if user else dummy_hash
    valid = verify_password(payload.password, stored_hash)

    if not user or not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = secrets.token_hex(32)
    return LoginResponse(
        token=token,
        token_type="bearer",
        username=user["username"],
        role=user["role"],
    )


@app.post(
    "/api/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Auth"],
    summary="Register new user account",
)
def register_user(
    payload: RegisterRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> RegisterResponse:
    """Register a new user account with default customer role. Extra fields are ignored."""
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (payload.username,))
    if cursor.fetchone() is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    hashed = hash_password(payload.password)
    cursor.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
        (payload.username, payload.email, hashed, "customer"),
    )
    conn.commit()

    return RegisterResponse(
        message="User registered successfully",
        username=payload.username,
        email=payload.email,
        role="customer",
    )


@app.post(
    "/api/feedback",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Feedback"],
    summary="Submit product feedback",
)
def submit_feedback(
    payload: FeedbackRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> FeedbackResponse:
    """Submit product feedback, validating product existence and escaping stored comment."""
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM products WHERE id = ?", (payload.product_id,))
    if cursor.fetchone() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found",
        )

    cursor.execute(
        "INSERT INTO feedback (product_id, comment) VALUES (?, ?)",
        (payload.product_id, payload.comment),
    )
    conn.commit()
    feedback_id = cursor.lastrowid or 1

    return FeedbackResponse(
        id=feedback_id,
        product_id=payload.product_id,
        comment=html.escape(payload.comment),
        status="received",
    )


@app.get(
    "/api/orders/{order_id}",
    response_model=OrderResponse,
    tags=["Orders"],
    summary="Retrieve customer order",
)
def get_order(
    order_id: Annotated[int, FPath(ge=1, description="Order ID to retrieve")],
) -> OrderResponse:
    """Return a demo canned order for testing order query flows."""
    return OrderResponse(
        order_id=order_id,
        status="shipped",
        customer="alice@demoshop.test",
        items=[
            OrderItem(product_id=1, name="Smartphone X", quantity=1, price=799.99),
            OrderItem(product_id=2, name="Noise-Cancelling Headphones", quantity=1, price=199.99),
        ],
        total=999.98,
        shipping_address=ShippingAddress(
            street="100 Innovation Way",
            city="Cyber City",
            country="IN",
            postal_code="560001",
        ),
        tracking_number=f"TRK-{order_id}-98765",
    )
