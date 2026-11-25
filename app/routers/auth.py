import secrets
import hmac

from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.config import TEMPLATES_DIR
from app.database import get_db
from app.models import User

from pwdlib import PasswordHash

router = APIRouter(tags=["Authentication"])

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

password_hash = PasswordHash.recommended()


def create_csrf_token(request: Request):
    token = secrets.token_urlsafe(32)
    request.session["csrf_token"] = token
    return token


def verify_csrf_token(request: Request, token: str):

    session_token = request.session.get("csrf_token")

    if not session_token or not hmac.compare_digest(session_token, token):
        raise HTTPException(status_code=403, detail="Invalid security token.")


@router.get("/login")
async def login_page(request: Request):

    csrf_token = create_csrf_token(request)

    return templates.TemplateResponse(
        request=request, name="login.html", context={"csrf_token": csrf_token}
    )


@router.get("/register")
async def register_page(request: Request):

    csrf_token = create_csrf_token(request)

    return templates.TemplateResponse(
        request=request, name="register.html", context={"csrf_token": csrf_token}
    )


@router.post("/register")
async def register_user(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):

    verify_csrf_token(request, csrf_token)

    full_name = full_name.strip()
    email = email.strip().lower()

    if not full_name or len(full_name) > 100:
        raise HTTPException(status_code=400, detail="Please enter a valid name.")

    if "@" not in email or len(email) > 255:
        raise HTTPException(
            status_code=400, detail="Please enter a valid email address."
        )

    if len(password) < 8 or len(password) > 128:
        raise HTTPException(
            status_code=400, detail="Password must contain 8 to 128 characters."
        )

    existing_user = db.query(User).filter(User.email == email).first()

    if existing_user:
        raise HTTPException(
            status_code=400, detail="An account with this email already exists."
        )

    new_user = User(
        full_name=full_name, email=email, hashed_password=password_hash.hash(password)
    )

    db.add(new_user)
    db.commit()

    return RedirectResponse(url="/login", status_code=303)


@router.post("/login")
async def login_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):

    verify_csrf_token(request, csrf_token)

    email = email.strip().lower()

    user = db.query(User).filter(User.email == email).first()

    if not user or not password_hash.verify(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    request.session.clear()

    request.session["user_id"] = user.id
    request.session["user_name"] = user.full_name

    create_csrf_token(request)

    return RedirectResponse(url="/", status_code=303)


@router.post("/logout")
async def logout_user(
    request: Request,
    csrf_token: str = Form(...),
):

    verify_csrf_token(request, csrf_token)

    request.session.clear()

    return RedirectResponse(url="/login", status_code=303)


def require_login(request: Request, db: Session = Depends(get_db)):

    user_id = request.session.get("user_id")

    if not user_id:
        raise HTTPException(status_code=303, headers={"Location": "/login"})

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        request.session.clear()

        raise HTTPException(status_code=303, headers={"Location": "/login"})

    return user
