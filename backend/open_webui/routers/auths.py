import re
import uuid
import time
import datetime
import logging
import smtplib # 新增
import os      # 新增
import random  # 新增
import string  # 新增
from email.mime.text import MIMEText # 新增
from email.header import Header      # 新增

from aiohttp import ClientSession
import urllib

from open_webui.models.auths import (
    AddUserForm,
    ApiKey,
    Auths,
    Token,
    LdapForm,
    SigninForm,
    SigninResponse,
    SignupForm,
    UpdatePasswordForm,
)
from open_webui.models.users import (
    UserProfileImageResponse,
    Users,
    UpdateProfileForm,
    UserStatus,
)
from open_webui.models.groups import Groups
from open_webui.models.oauth_sessions import OAuthSessions

from open_webui.constants import ERROR_MESSAGES, WEBHOOK_MESSAGES
from open_webui.env import (
    WEBUI_AUTH,
    WEBUI_AUTH_TRUSTED_EMAIL_HEADER,
    WEBUI_AUTH_TRUSTED_NAME_HEADER,
    WEBUI_AUTH_TRUSTED_GROUPS_HEADER,
    WEBUI_AUTH_COOKIE_SAME_SITE,
    WEBUI_AUTH_COOKIE_SECURE,
    WEBUI_AUTH_SIGNOUT_REDIRECT_URL,
    ENABLE_INITIAL_ADMIN_SIGNUP,
)
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response, JSONResponse
from open_webui.config import (
    OPENID_PROVIDER_URL,
    ENABLE_OAUTH_SIGNUP,
    ENABLE_LDAP,
    ENABLE_PASSWORD_AUTH,
)
from pydantic import BaseModel

from open_webui.utils.misc import parse_duration, validate_email_format
from open_webui.utils.auth import (
    validate_password,
    verify_password,
    decode_token,
    invalidate_token,
    create_api_key,
    create_token,
    get_admin_user,
    get_verified_user,
    get_current_user,
    get_password_hash,
    get_http_authorization_cred,
)
from open_webui.internal.db import get_session
from sqlalchemy.orm import Session
from open_webui.utils.webhook import post_webhook
from open_webui.utils.access_control import get_permissions, has_permission
from open_webui.utils.groups import apply_default_group_assignment

from open_webui.utils.redis import get_redis_client
from open_webui.utils.rate_limit import RateLimiter


from typing import Optional, List

from ssl import CERT_NONE, CERT_REQUIRED, PROTOCOL_TLS

from ldap3 import Server, Connection, NONE, Tls
from ldap3.utils.conv import escape_filter_chars

router = APIRouter()

log = logging.getLogger(__name__)

signin_rate_limiter = RateLimiter(
    redis_client=get_redis_client(), limit=5 * 3, window=60 * 3
)
# --- 放在 auths.py 的辅助函数区域 ---

def validate_email_format(email: str) -> bool:
    """
    后端严格校验邮箱格式
    """
    # 这是一个比较通用的邮箱正则
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password: str):
    """
    后端校验密码强度
    """
    if len(password) < 8:
        raise Exception("密码长度不能少于 8 位")
    # 如果需要强制包含数字和字母，取消下面注释
    if not re.search(r"\d", password) or not re.search(r"[a-zA-Z]", password):
         raise Exception("密码必须同时包含字母和数字")
# ==========================================
# 辅助函数: 发送邮件 (通用)
# ==========================================
def send_email_code(to_email: str, code: str, subject: str = "Verification Code"):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM", smtp_user)
    
    if not smtp_host or not smtp_user:
        log.error("SMTP not configured in .env, skipping email.")
        return

    msg = MIMEText(f"Your code is: {code}\nExpires in 10 minutes.", 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = smtp_from
    msg['To'] = to_email

    try:
        # --- [Sean Fix] 区分 465 SSL 和其他端口 ---
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_host, smtp_port)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
            
        with server:
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, [to_email], msg.as_string())
    except Exception as e:
        log.error(f"Failed to send email: {e}")

############################
# GetSessionUser
############################


class SessionUserResponse(Token, UserProfileImageResponse):
    expires_at: Optional[int] = None
    permissions: Optional[dict] = None


class SessionUserInfoResponse(SessionUserResponse, UserStatus):
    bio: Optional[str] = None
    gender: Optional[str] = None
    date_of_birth: Optional[datetime.date] = None


@router.get("/", response_model=SessionUserInfoResponse)
async def get_session_user(
    request: Request,
    response: Response,
    user=Depends(get_current_user),
    db: Session = Depends(get_session),
):

    auth_header = request.headers.get("Authorization")
    auth_token = get_http_authorization_cred(auth_header)
    token = auth_token.credentials
    data = decode_token(token)

    expires_at = None

    if data:
        expires_at = data.get("exp")

        if (expires_at is not None) and int(time.time()) > expires_at:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.INVALID_TOKEN,
            )

        # Set the cookie token
        response.set_cookie(
            key="token",
            value=token,
            expires=(
                datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
                if expires_at
                else None
            ),
            httponly=True,  # Ensures the cookie is not accessible via JavaScript
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

    user_permissions = get_permissions(
        user.id, request.app.state.config.USER_PERMISSIONS, db=db
    )

    return {
        "token": token,
        "token_type": "Bearer",
        "expires_at": expires_at,
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "profile_image_url": user.profile_image_url,
        "bio": user.bio,
        "gender": user.gender,
        "date_of_birth": user.date_of_birth,
        "status_emoji": user.status_emoji,
        "status_message": user.status_message,
        "status_expires_at": user.status_expires_at,
        "permissions": user_permissions,
    }


############################
# Update Profile
############################


@router.post("/update/profile", response_model=UserProfileImageResponse)
async def update_profile(
    form_data: UpdateProfileForm,
    session_user=Depends(get_verified_user),
    db: Session = Depends(get_session),
):
    if session_user:
        user = Users.update_user_by_id(
            session_user.id,
            form_data.model_dump(),
            db=db,
        )
        if user:
            return user
        else:
            raise HTTPException(400, detail=ERROR_MESSAGES.DEFAULT())
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)


############################
# Update Timezone
############################


class UpdateTimezoneForm(BaseModel):
    timezone: str


@router.post("/update/timezone")
async def update_timezone(
    form_data: UpdateTimezoneForm,
    session_user=Depends(get_current_user),
    db: Session = Depends(get_session),
):
    if session_user:
        Users.update_user_by_id(
            session_user.id,
            {"timezone": form_data.timezone},
            db=db,
        )
        return {"status": True}
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)


############################
# Update Password
############################


@router.post("/update/password", response_model=bool)
async def update_password(
    form_data: UpdatePasswordForm,
    session_user=Depends(get_current_user),
    db: Session = Depends(get_session),
):
    if WEBUI_AUTH_TRUSTED_EMAIL_HEADER:
        raise HTTPException(400, detail=ERROR_MESSAGES.ACTION_PROHIBITED)
    if session_user:
        user = Auths.authenticate_user(
            session_user.email,
            lambda pw: verify_password(form_data.password, pw),
            db=db,
        )

        if user:
            try:
                validate_password(form_data.password)
            except Exception as e:
                raise HTTPException(400, detail=str(e))
            hashed = get_password_hash(form_data.new_password)
            return Auths.update_user_password_by_id(user.id, hashed, db=db)
        else:
            raise HTTPException(400, detail=ERROR_MESSAGES.INCORRECT_PASSWORD)
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)


############################
# LDAP Authentication
############################
@router.post("/ldap", response_model=SessionUserResponse)
async def ldap_auth(
    request: Request,
    response: Response,
    form_data: LdapForm,
    db: Session = Depends(get_session),
):
    # Security checks FIRST - before loading any config
    if not request.app.state.config.ENABLE_LDAP:
        raise HTTPException(400, detail="LDAP authentication is not enabled")

    if not ENABLE_PASSWORD_AUTH:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.ACTION_PROHIBITED,
        )

    # NOW load LDAP config variables
    LDAP_SERVER_LABEL = request.app.state.config.LDAP_SERVER_LABEL
    LDAP_SERVER_HOST = request.app.state.config.LDAP_SERVER_HOST
    LDAP_SERVER_PORT = request.app.state.config.LDAP_SERVER_PORT
    LDAP_ATTRIBUTE_FOR_MAIL = request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL
    LDAP_ATTRIBUTE_FOR_USERNAME = request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME
    LDAP_SEARCH_BASE = request.app.state.config.LDAP_SEARCH_BASE
    LDAP_SEARCH_FILTERS = request.app.state.config.LDAP_SEARCH_FILTERS
    LDAP_APP_DN = request.app.state.config.LDAP_APP_DN
    LDAP_APP_PASSWORD = request.app.state.config.LDAP_APP_PASSWORD
    LDAP_USE_TLS = request.app.state.config.LDAP_USE_TLS
    LDAP_CA_CERT_FILE = request.app.state.config.LDAP_CA_CERT_FILE
    LDAP_VALIDATE_CERT = (
        CERT_REQUIRED if request.app.state.config.LDAP_VALIDATE_CERT else CERT_NONE
    )
    LDAP_CIPHERS = (
        request.app.state.config.LDAP_CIPHERS
        if request.app.state.config.LDAP_CIPHERS
        else "ALL"
    )

    try:
        tls = Tls(
            validate=LDAP_VALIDATE_CERT,
            version=PROTOCOL_TLS,
            ca_certs_file=LDAP_CA_CERT_FILE,
            ciphers=LDAP_CIPHERS,
        )
    except Exception as e:
        log.error(f"TLS configuration error: {str(e)}")
        raise HTTPException(400, detail="Failed to configure TLS for LDAP connection.")

    try:
        server = Server(
            host=LDAP_SERVER_HOST,
            port=LDAP_SERVER_PORT,
            get_info=NONE,
            use_ssl=LDAP_USE_TLS,
            tls=tls,
        )
        connection_app = Connection(
            server,
            LDAP_APP_DN,
            LDAP_APP_PASSWORD,
            auto_bind="NONE",
            authentication="SIMPLE" if LDAP_APP_DN else "ANONYMOUS",
        )
        if not connection_app.bind():
            raise HTTPException(400, detail="Application account bind failed")

        ENABLE_LDAP_GROUP_MANAGEMENT = (
            request.app.state.config.ENABLE_LDAP_GROUP_MANAGEMENT
        )
        ENABLE_LDAP_GROUP_CREATION = request.app.state.config.ENABLE_LDAP_GROUP_CREATION
        LDAP_ATTRIBUTE_FOR_GROUPS = request.app.state.config.LDAP_ATTRIBUTE_FOR_GROUPS

        search_attributes = [
            f"{LDAP_ATTRIBUTE_FOR_USERNAME}",
            f"{LDAP_ATTRIBUTE_FOR_MAIL}",
            "cn",
        ]
        if ENABLE_LDAP_GROUP_MANAGEMENT:
            search_attributes.append(f"{LDAP_ATTRIBUTE_FOR_GROUPS}")
            log.info(
                f"LDAP Group Management enabled. Adding {LDAP_ATTRIBUTE_FOR_GROUPS} to search attributes"
            )
        log.info(f"LDAP search attributes: {search_attributes}")

        search_success = connection_app.search(
            search_base=LDAP_SEARCH_BASE,
            search_filter=f"(&({LDAP_ATTRIBUTE_FOR_USERNAME}={escape_filter_chars(form_data.user.lower())}){LDAP_SEARCH_FILTERS})",
            attributes=search_attributes,
        )
        if not search_success or not connection_app.entries:
            raise HTTPException(400, detail="User not found in the LDAP server")

        entry = connection_app.entries[0]
        entry_username = entry[f"{LDAP_ATTRIBUTE_FOR_USERNAME}"].value
        email = entry[
            f"{LDAP_ATTRIBUTE_FOR_MAIL}"
        ].value  # retrieve the Attribute value

        username_list = []  # list of usernames from LDAP attribute
        if isinstance(entry_username, list):
            username_list = [str(name).lower() for name in entry_username]
        else:
            username_list = [str(entry_username).lower()]

        # TODO: support multiple emails if LDAP returns a list
        if not email:
            raise HTTPException(400, "User does not have a valid email address.")
        elif isinstance(email, str):
            email = email.lower()
        elif isinstance(email, list):
            email = email[0].lower()
        else:
            email = str(email).lower()

        cn = str(entry["cn"])  # common name
        user_dn = entry.entry_dn  # user distinguished name

        user_groups = []
        if ENABLE_LDAP_GROUP_MANAGEMENT and LDAP_ATTRIBUTE_FOR_GROUPS in entry:
            group_dns = entry[LDAP_ATTRIBUTE_FOR_GROUPS]
            log.info(f"LDAP raw group DNs for user {username_list}: {group_dns}")

            if group_dns:
                log.info(f"LDAP group_dns original: {group_dns}")
                log.info(f"LDAP group_dns type: {type(group_dns)}")
                log.info(f"LDAP group_dns length: {len(group_dns)}")

                if hasattr(group_dns, "value"):
                    group_dns = group_dns.value
                    log.info(f"Extracted .value property: {group_dns}")
                elif hasattr(group_dns, "__iter__") and not isinstance(
                    group_dns, (str, bytes)
                ):
                    group_dns = list(group_dns)
                    log.info(f"Converted to list: {group_dns}")

                if isinstance(group_dns, list):
                    group_dns = [str(item) for item in group_dns]
                else:
                    group_dns = [str(group_dns)]

                log.info(
                    f"LDAP group_dns after processing - type: {type(group_dns)}, length: {len(group_dns)}"
                )

                for group_idx, group_dn in enumerate(group_dns):
                    group_dn = str(group_dn)
                    log.info(f"Processing group DN #{group_idx + 1}: {group_dn}")

                    try:
                        group_cn = None

                        for item in group_dn.split(","):
                            item = item.strip()
                            if item.upper().startswith("CN="):
                                group_cn = item[3:]
                                break

                        if group_cn:
                            user_groups.append(group_cn)

                        else:
                            log.warning(
                                f"Could not extract CN from group DN: {group_dn}"
                            )
                    except Exception as e:
                        log.warning(
                            f"Failed to extract group name from DN {group_dn}: {e}"
                        )

                log.info(
                    f"LDAP groups for user {username_list}: {user_groups} (total: {len(user_groups)})"
                )
            else:
                log.info(f"No groups found for user {username_list}")
        elif ENABLE_LDAP_GROUP_MANAGEMENT:
            log.warning(
                f"LDAP Group Management enabled but {LDAP_ATTRIBUTE_FOR_GROUPS} attribute not found in user entry"
            )

        if username_list and form_data.user.lower() in username_list:
            connection_user = Connection(
                server,
                user_dn,
                form_data.password,
                auto_bind="NONE",
                authentication="SIMPLE",
            )
            if not connection_user.bind():
                raise HTTPException(400, "Authentication failed.")

            user = Users.get_user_by_email(email, db=db)
            if not user:
                try:
                    role = (
                        "admin"
                        if not Users.has_users(db=db)
                        else request.app.state.config.DEFAULT_USER_ROLE
                    )

                    user = Auths.insert_new_auth(
                        email=email,
                        password=str(uuid.uuid4()),
                        name=cn,
                        role=role,
                        db=db,
                    )

                    if not user:
                        raise HTTPException(
                            500, detail=ERROR_MESSAGES.CREATE_USER_ERROR
                        )

                    apply_default_group_assignment(
                        request.app.state.config.DEFAULT_GROUP_ID,
                        user.id,
                        db=db,
                    )

                except HTTPException:
                    raise
                except Exception as err:
                    log.error(f"LDAP user creation error: {str(err)}")
                    raise HTTPException(
                        500, detail="Internal error occurred during LDAP user creation."
                    )

            user = Auths.authenticate_user_by_email(email, db=db)

            if user:
                expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
                expires_at = None
                if expires_delta:
                    expires_at = int(time.time()) + int(expires_delta.total_seconds())

                token = create_token(
                    data={"id": user.id},
                    expires_delta=expires_delta,
                )

                # Set the cookie token
                response.set_cookie(
                    key="token",
                    value=token,
                    expires=(
                        datetime.datetime.fromtimestamp(
                            expires_at, datetime.timezone.utc
                        )
                        if expires_at
                        else None
                    ),
                    httponly=True,  # Ensures the cookie is not accessible via JavaScript
                    samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
                    secure=WEBUI_AUTH_COOKIE_SECURE,
                )

                user_permissions = get_permissions(
                    user.id, request.app.state.config.USER_PERMISSIONS, db=db
                )

                if (
                    user.role != "admin"
                    and ENABLE_LDAP_GROUP_MANAGEMENT
                    and user_groups
                ):
                    if ENABLE_LDAP_GROUP_CREATION:
                        Groups.create_groups_by_group_names(user.id, user_groups, db=db)
                    try:
                        Groups.sync_groups_by_group_names(user.id, user_groups, db=db)
                        log.info(
                            f"Successfully synced groups for user {user.id}: {user_groups}"
                        )
                    except Exception as e:
                        log.error(f"Failed to sync groups for user {user.id}: {e}")

                return {
                    "token": token,
                    "token_type": "Bearer",
                    "expires_at": expires_at,
                    "id": user.id,
                    "email": user.email,
                    "name": user.name,
                    "role": user.role,
                    "profile_image_url": user.profile_image_url,
                    "permissions": user_permissions,
                }
            else:
                raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)
        else:
            raise HTTPException(400, "User record mismatch.")
    except Exception as e:
        log.error(f"LDAP authentication error: {str(e)}")
        raise HTTPException(400, detail="LDAP authentication failed.")


############################
# SignIn
############################


@router.post("/signin", response_model=SessionUserResponse)
async def signin(
    request: Request,
    response: Response,
    form_data: SigninForm,
    db: Session = Depends(get_session),
):
    if not ENABLE_PASSWORD_AUTH:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.ACTION_PROHIBITED,
        )

    if WEBUI_AUTH_TRUSTED_EMAIL_HEADER:
        if WEBUI_AUTH_TRUSTED_EMAIL_HEADER not in request.headers:
            raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_TRUSTED_HEADER)

        email = request.headers[WEBUI_AUTH_TRUSTED_EMAIL_HEADER].lower()
        name = email

        if WEBUI_AUTH_TRUSTED_NAME_HEADER:
            name = request.headers.get(WEBUI_AUTH_TRUSTED_NAME_HEADER, email)
            try:
                name = urllib.parse.unquote(name, encoding="utf-8")
            except Exception as e:
                pass

        if not Users.get_user_by_email(email.lower(), db=db):
            await signup(
                request,
                response,
                SignupForm(email=email, password=str(uuid.uuid4()), name=name),
                db=db,
            )

        user = Auths.authenticate_user_by_email(email, db=db)
        if WEBUI_AUTH_TRUSTED_GROUPS_HEADER and user and user.role != "admin":
            group_names = request.headers.get(
                WEBUI_AUTH_TRUSTED_GROUPS_HEADER, ""
            ).split(",")
            group_names = [name.strip() for name in group_names if name.strip()]

            if group_names:
                Groups.sync_groups_by_group_names(user.id, group_names, db=db)

    elif WEBUI_AUTH == False:
        admin_email = "admin@localhost"
        admin_password = "admin"

        if Users.get_user_by_email(admin_email.lower(), db=db):
            user = Auths.authenticate_user(
                admin_email.lower(),
                lambda pw: verify_password(admin_password, pw),
                db=db,
            )
        else:
            if Users.has_users(db=db):
                raise HTTPException(400, detail=ERROR_MESSAGES.EXISTING_USERS)

            await signup(
                request,
                response,
                SignupForm(email=admin_email, password=admin_password, name="User"),
                db=db,
            )

            user = Auths.authenticate_user(
                admin_email.lower(),
                lambda pw: verify_password(admin_password, pw),
                db=db,
            )
    else:
        if signin_rate_limiter.is_limited(form_data.email.lower()):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=ERROR_MESSAGES.RATE_LIMIT_EXCEEDED,
            )

        password_bytes = form_data.password.encode("utf-8")
        if len(password_bytes) > 72:
            # TODO: Implement other hashing algorithms that support longer passwords
            log.info("Password too long, truncating to 72 bytes for bcrypt")
            password_bytes = password_bytes[:72]

            # decode safely — ignore incomplete UTF-8 sequences
            form_data.password = password_bytes.decode("utf-8", errors="ignore")

        user = Auths.authenticate_user(
            form_data.email.lower(),
            lambda pw: verify_password(form_data.password, pw),
            db=db,
        )

    if user:

        expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
        expires_at = None
        if expires_delta:
            expires_at = int(time.time()) + int(expires_delta.total_seconds())

        token = create_token(
            data={"id": user.id},
            expires_delta=expires_delta,
        )

        datetime_expires_at = (
            datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc)
            if expires_at
            else None
        )

        # Set the cookie token
        response.set_cookie(
            key="token",
            value=token,
            expires=datetime_expires_at,
            httponly=True,  # Ensures the cookie is not accessible via JavaScript
            samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
            secure=WEBUI_AUTH_COOKIE_SECURE,
        )

        user_permissions = get_permissions(
            user.id, request.app.state.config.USER_PERMISSIONS, db=db
        )

        return {
            "token": token,
            "token_type": "Bearer",
            "expires_at": expires_at,
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "profile_image_url": user.profile_image_url,
            "permissions": user_permissions,
        }
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.INVALID_CRED)


############################
# SignUp (Modified)
############################

@router.post("/signup", response_model=SessionUserResponse)
async def signup(
    request: Request,
    response: Response,
    form_data: SignupForm,
    db: Session = Depends(get_session),
):
    # 1. --- 🛡️ 第一道防线：格式校验 (最先执行) ---
    # 校验邮箱格式
    if not validate_email_format(form_data.email.lower()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="邮箱格式不正确，请检查输入" # ERROR_MESSAGES.INVALID_EMAIL_FORMAT
        )

    # 校验密码强度
    try:
        validate_password(form_data.password)
    except Exception as e:
        # 直接把具体的错误信息（如“长度不够”）返给前端
        raise HTTPException(status_code=400, detail=str(e))

    # 2. --- 逻辑准备 ---
    email_lower = form_data.email.lower()
    has_users = Users.has_users(db=db)
    
    # 3. --- 🛡️ 第二道防线：用户状态检查 ---
    existing_user = Users.get_user_by_email(email_lower, db=db)

    # 如果用户存在
    if existing_user:
        # 只有 Pending 状态允许被“覆盖/重新激活”
        if existing_user.role == "pending":
            hashed = get_password_hash(form_data.password)
            Auths.update_user_password_by_id(existing_user.id, hashed, db=db)
            Users.update_user_by_id(
                existing_user.id, 
                {"name": form_data.name, "profile_image_url": form_data.profile_image_url}, 
                db=db
            )
            user = existing_user
            role = "pending"
        else:
            # 既然是已存在的正式用户，直接报错，不允许重复注册
            raise HTTPException(400, detail=ERROR_MESSAGES.EMAIL_TAKEN)
            
    # 如果用户不存在，创建新用户
    else:
        hashed = get_password_hash(form_data.password)
        # 第一个用户是 admin，后续都是 pending
        role = "admin" if not has_users else "pending"
        
        user = Auths.insert_new_auth(
            email_lower, hashed, form_data.name, form_data.profile_image_url, role, db=db,
        )

    # 4. --- 业务逻辑：分流处理 ---
    if user:
        # Case A: Admin 直接给 Token 登录
        if role == "admin":
            expires_delta = parse_duration(request.app.state.config.JWT_EXPIRES_IN)
            expires_at = int(time.time()) + int(expires_delta.total_seconds()) if expires_delta else None
            
            token = create_token(data={"id": user.id}, expires_delta=expires_delta)
            
            # 设置 Cookie
            response.set_cookie(
                key="token",
                value=token,
                expires=datetime.datetime.fromtimestamp(expires_at, datetime.timezone.utc) if expires_at else None,
                httponly=True,
                samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
                secure=WEBUI_AUTH_COOKIE_SECURE,
            )

            # 自动应用权限和组
            if not has_users:
                 # 创建完第一个管理员后，可以在内存里把注册关了（可选）
                 request.app.state.config.ENABLE_SIGNUP = False

            user_permissions = get_permissions(user.id, request.app.state.config.USER_PERMISSIONS, db=db)
            apply_default_group_assignment(request.app.state.config.DEFAULT_GROUP_ID, user.id, db=db)

            return {
                "token": token,
                "token_type": "Bearer",
                "expires_at": expires_at,
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "profile_image_url": user.profile_image_url,
                "permissions": user_permissions,
            }

        # Case B: 普通用户，进入 Pending 验证流程
        else:
            # 生成 6 位数字验证码
            code = ''.join(random.choices(string.digits, k=6))
            
            # 存入 Redis (10分钟有效期)
            # 这里的 get_redis_client 确保你前面 import 了，或者用 request.app.state.redis
            try:
                redis_client = get_redis_client()
                # 关键：加上 print 方便你在终端调试看验证码，避免发邮件失败不知道码是多少
                print(f"DEBUG: Email={user.email}, Code={code}") 
                redis_client.setex(f"verification:{user.email.lower()}", 600, code)
            except Exception as e:
                log.error(f"Redis error: {e}")
                raise HTTPException(500, detail="验证服务暂不可用(Redis连接失败)")

            # 发送邮件 (如果配置了)
            # 建议加个 try-except 避免邮件发不出去导致前端崩了
            try:
                send_email_code(user.email, code, "Verify your account")
            except Exception as e:
                log.error(f"Email send error: {e}")
                # 这里不报错，因为你可以在终端看到验证码，或者假设 Redis 已经存了

            # 抛出 401 给前端，前端捕获后弹出验证码输入框
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="VERIFICATION_REQUIRED"
            )

    else:
        raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_USER_ERROR)


@router.get("/signout")
async def signout(
    request: Request, response: Response, db: Session = Depends(get_session)
):

    # get auth token from headers or cookies
    token = None
    auth_header = request.headers.get("Authorization")
    if auth_header:
        auth_cred = get_http_authorization_cred(auth_header)
        token = auth_cred.credentials
    else:
        token = request.cookies.get("token")

    if token:
        await invalidate_token(request, token)

    response.delete_cookie("token")
    response.delete_cookie("oui-session")
    response.delete_cookie("oauth_id_token")

    oauth_session_id = request.cookies.get("oauth_session_id")
    if oauth_session_id:
        response.delete_cookie("oauth_session_id")

        session = OAuthSessions.get_session_by_id(oauth_session_id, db=db)
        oauth_server_metadata_url = (
            request.app.state.oauth_manager.get_server_metadata_url(session.provider)
            if session
            else None
        ) or OPENID_PROVIDER_URL.value

        if session and oauth_server_metadata_url:
            oauth_id_token = session.token.get("id_token")
            try:
                async with ClientSession(trust_env=True) as session:
                    async with session.get(oauth_server_metadata_url) as r:
                        if r.status == 200:
                            openid_data = await r.json()
                            logout_url = openid_data.get("end_session_endpoint")

                            if logout_url:
                                return JSONResponse(
                                    status_code=200,
                                    content={
                                        "status": True,
                                        "redirect_url": f"{logout_url}?id_token_hint={oauth_id_token}"
                                        + (
                                            f"&post_logout_redirect_uri={WEBUI_AUTH_SIGNOUT_REDIRECT_URL}"
                                            if WEBUI_AUTH_SIGNOUT_REDIRECT_URL
                                            else ""
                                        ),
                                    },
                                    headers=response.headers,
                                )
                        else:
                            raise Exception("Failed to fetch OpenID configuration")

            except Exception as e:
                log.error(f"OpenID signout error: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail="Failed to sign out from the OpenID provider.",
                    headers=response.headers,
                )

    if WEBUI_AUTH_SIGNOUT_REDIRECT_URL:
        return JSONResponse(
            status_code=200,
            content={
                "status": True,
                "redirect_url": WEBUI_AUTH_SIGNOUT_REDIRECT_URL,
            },
            headers=response.headers,
        )

    return JSONResponse(
        status_code=200, content={"status": True}, headers=response.headers
    )


############################
# AddUser
############################


@router.post("/add", response_model=SigninResponse)
async def add_user(
    request: Request,
    form_data: AddUserForm,
    user=Depends(get_admin_user),
    db: Session = Depends(get_session),
):
    if not validate_email_format(form_data.email.lower()):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail=ERROR_MESSAGES.INVALID_EMAIL_FORMAT
        )

    if Users.get_user_by_email(form_data.email.lower(), db=db):
        raise HTTPException(400, detail=ERROR_MESSAGES.EMAIL_TAKEN)

    try:
        try:
            validate_password(form_data.password)
        except Exception as e:
            raise HTTPException(400, detail=str(e))

        hashed = get_password_hash(form_data.password)
        user = Auths.insert_new_auth(
            form_data.email.lower(),
            hashed,
            form_data.name,
            form_data.profile_image_url,
            form_data.role,
            db=db,
        )

        if user:
            apply_default_group_assignment(
                request.app.state.config.DEFAULT_GROUP_ID,
                user.id,
                db=db,
            )

            token = create_token(data={"id": user.id})
            return {
                "token": token,
                "token_type": "Bearer",
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "profile_image_url": user.profile_image_url,
            }
        else:
            raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_USER_ERROR)
    except Exception as err:
        log.error(f"Add user error: {str(err)}")
        raise HTTPException(
            500, detail="An internal error occurred while adding the user."
        )


############################
# GetAdminDetails
############################


@router.get("/admin/details")
async def get_admin_details(
    request: Request, user=Depends(get_current_user), db: Session = Depends(get_session)
):
    if request.app.state.config.SHOW_ADMIN_DETAILS:
        admin_email = request.app.state.config.ADMIN_EMAIL
        admin_name = None

        log.info(f"Admin details - Email: {admin_email}, Name: {admin_name}")

        if admin_email:
            admin = Users.get_user_by_email(admin_email, db=db)
            if admin:
                admin_name = admin.name
        else:
            admin = Users.get_first_user(db=db)
            if admin:
                admin_email = admin.email
                admin_name = admin.name

        return {
            "name": admin_name,
            "email": admin_email,
        }
    else:
        raise HTTPException(400, detail=ERROR_MESSAGES.ACTION_PROHIBITED)


############################
# ToggleSignUp
############################


@router.get("/admin/config")
async def get_admin_config(request: Request, user=Depends(get_admin_user)):
    return {
        "SHOW_ADMIN_DETAILS": request.app.state.config.SHOW_ADMIN_DETAILS,
        "ADMIN_EMAIL": request.app.state.config.ADMIN_EMAIL,
        "WEBUI_URL": request.app.state.config.WEBUI_URL,
        "ENABLE_SIGNUP": request.app.state.config.ENABLE_SIGNUP,
        "ENABLE_API_KEYS": request.app.state.config.ENABLE_API_KEYS,
        "ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS": request.app.state.config.ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS,
        "API_KEYS_ALLOWED_ENDPOINTS": request.app.state.config.API_KEYS_ALLOWED_ENDPOINTS,
        "DEFAULT_USER_ROLE": request.app.state.config.DEFAULT_USER_ROLE,
        "DEFAULT_GROUP_ID": request.app.state.config.DEFAULT_GROUP_ID,
        "JWT_EXPIRES_IN": request.app.state.config.JWT_EXPIRES_IN,
        "ENABLE_COMMUNITY_SHARING": request.app.state.config.ENABLE_COMMUNITY_SHARING,
        "ENABLE_MESSAGE_RATING": request.app.state.config.ENABLE_MESSAGE_RATING,
        "ENABLE_FOLDERS": request.app.state.config.ENABLE_FOLDERS,
        "FOLDER_MAX_FILE_COUNT": request.app.state.config.FOLDER_MAX_FILE_COUNT,
        "ENABLE_CHANNELS": request.app.state.config.ENABLE_CHANNELS,
        "ENABLE_MEMORIES": request.app.state.config.ENABLE_MEMORIES,
        "ENABLE_NOTES": request.app.state.config.ENABLE_NOTES,
        "ENABLE_USER_WEBHOOKS": request.app.state.config.ENABLE_USER_WEBHOOKS,
        "ENABLE_USER_STATUS": request.app.state.config.ENABLE_USER_STATUS,
        "PENDING_USER_OVERLAY_TITLE": request.app.state.config.PENDING_USER_OVERLAY_TITLE,
        "PENDING_USER_OVERLAY_CONTENT": request.app.state.config.PENDING_USER_OVERLAY_CONTENT,
        "RESPONSE_WATERMARK": request.app.state.config.RESPONSE_WATERMARK,
    }


class AdminConfig(BaseModel):
    SHOW_ADMIN_DETAILS: bool
    ADMIN_EMAIL: Optional[str] = None
    WEBUI_URL: str
    ENABLE_SIGNUP: bool
    ENABLE_API_KEYS: bool
    ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS: bool
    API_KEYS_ALLOWED_ENDPOINTS: str
    DEFAULT_USER_ROLE: str
    DEFAULT_GROUP_ID: str
    JWT_EXPIRES_IN: str
    ENABLE_COMMUNITY_SHARING: bool
    ENABLE_MESSAGE_RATING: bool
    ENABLE_FOLDERS: bool
    FOLDER_MAX_FILE_COUNT: Optional[int | str] = None
    ENABLE_CHANNELS: bool
    ENABLE_MEMORIES: bool
    ENABLE_NOTES: bool
    ENABLE_USER_WEBHOOKS: bool
    ENABLE_USER_STATUS: bool
    PENDING_USER_OVERLAY_TITLE: Optional[str] = None
    PENDING_USER_OVERLAY_CONTENT: Optional[str] = None
    RESPONSE_WATERMARK: Optional[str] = None


@router.post("/admin/config")
async def update_admin_config(
    request: Request, form_data: AdminConfig, user=Depends(get_admin_user)
):
    request.app.state.config.SHOW_ADMIN_DETAILS = form_data.SHOW_ADMIN_DETAILS
    request.app.state.config.ADMIN_EMAIL = form_data.ADMIN_EMAIL
    request.app.state.config.WEBUI_URL = form_data.WEBUI_URL
    request.app.state.config.ENABLE_SIGNUP = form_data.ENABLE_SIGNUP

    request.app.state.config.ENABLE_API_KEYS = form_data.ENABLE_API_KEYS
    request.app.state.config.ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS = (
        form_data.ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS
    )
    request.app.state.config.API_KEYS_ALLOWED_ENDPOINTS = (
        form_data.API_KEYS_ALLOWED_ENDPOINTS
    )

    request.app.state.config.ENABLE_FOLDERS = form_data.ENABLE_FOLDERS
    request.app.state.config.FOLDER_MAX_FILE_COUNT = (
        int(form_data.FOLDER_MAX_FILE_COUNT) if form_data.FOLDER_MAX_FILE_COUNT else ""
    )
    request.app.state.config.ENABLE_CHANNELS = form_data.ENABLE_CHANNELS
    request.app.state.config.ENABLE_MEMORIES = form_data.ENABLE_MEMORIES
    request.app.state.config.ENABLE_NOTES = form_data.ENABLE_NOTES

    if form_data.DEFAULT_USER_ROLE in ["pending", "user", "admin"]:
        request.app.state.config.DEFAULT_USER_ROLE = form_data.DEFAULT_USER_ROLE

    request.app.state.config.DEFAULT_GROUP_ID = form_data.DEFAULT_GROUP_ID

    pattern = r"^(-1|0|(-?\d+(\.\d+)?)(ms|s|m|h|d|w))$"

    # Check if the input string matches the pattern
    if re.match(pattern, form_data.JWT_EXPIRES_IN):
        request.app.state.config.JWT_EXPIRES_IN = form_data.JWT_EXPIRES_IN

    request.app.state.config.ENABLE_COMMUNITY_SHARING = (
        form_data.ENABLE_COMMUNITY_SHARING
    )
    request.app.state.config.ENABLE_MESSAGE_RATING = form_data.ENABLE_MESSAGE_RATING

    request.app.state.config.ENABLE_USER_WEBHOOKS = form_data.ENABLE_USER_WEBHOOKS
    request.app.state.config.ENABLE_USER_STATUS = form_data.ENABLE_USER_STATUS

    request.app.state.config.PENDING_USER_OVERLAY_TITLE = (
        form_data.PENDING_USER_OVERLAY_TITLE
    )
    request.app.state.config.PENDING_USER_OVERLAY_CONTENT = (
        form_data.PENDING_USER_OVERLAY_CONTENT
    )

    request.app.state.config.RESPONSE_WATERMARK = form_data.RESPONSE_WATERMARK

    return {
        "SHOW_ADMIN_DETAILS": request.app.state.config.SHOW_ADMIN_DETAILS,
        "ADMIN_EMAIL": request.app.state.config.ADMIN_EMAIL,
        "WEBUI_URL": request.app.state.config.WEBUI_URL,
        "ENABLE_SIGNUP": request.app.state.config.ENABLE_SIGNUP,
        "ENABLE_API_KEYS": request.app.state.config.ENABLE_API_KEYS,
        "ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS": request.app.state.config.ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS,
        "API_KEYS_ALLOWED_ENDPOINTS": request.app.state.config.API_KEYS_ALLOWED_ENDPOINTS,
        "DEFAULT_USER_ROLE": request.app.state.config.DEFAULT_USER_ROLE,
        "DEFAULT_GROUP_ID": request.app.state.config.DEFAULT_GROUP_ID,
        "JWT_EXPIRES_IN": request.app.state.config.JWT_EXPIRES_IN,
        "ENABLE_COMMUNITY_SHARING": request.app.state.config.ENABLE_COMMUNITY_SHARING,
        "ENABLE_MESSAGE_RATING": request.app.state.config.ENABLE_MESSAGE_RATING,
        "ENABLE_FOLDERS": request.app.state.config.ENABLE_FOLDERS,
        "FOLDER_MAX_FILE_COUNT": request.app.state.config.FOLDER_MAX_FILE_COUNT,
        "ENABLE_CHANNELS": request.app.state.config.ENABLE_CHANNELS,
        "ENABLE_MEMORIES": request.app.state.config.ENABLE_MEMORIES,
        "ENABLE_NOTES": request.app.state.config.ENABLE_NOTES,
        "ENABLE_USER_WEBHOOKS": request.app.state.config.ENABLE_USER_WEBHOOKS,
        "ENABLE_USER_STATUS": request.app.state.config.ENABLE_USER_STATUS,
        "PENDING_USER_OVERLAY_TITLE": request.app.state.config.PENDING_USER_OVERLAY_TITLE,
        "PENDING_USER_OVERLAY_CONTENT": request.app.state.config.PENDING_USER_OVERLAY_CONTENT,
        "RESPONSE_WATERMARK": request.app.state.config.RESPONSE_WATERMARK,
    }


class LdapServerConfig(BaseModel):
    label: str
    host: str
    port: Optional[int] = None
    attribute_for_mail: str = "mail"
    attribute_for_username: str = "uid"
    app_dn: str
    app_dn_password: str
    search_base: str
    search_filters: str = ""
    use_tls: bool = True
    certificate_path: Optional[str] = None
    validate_cert: bool = True
    ciphers: Optional[str] = "ALL"


@router.get("/admin/config/ldap/server", response_model=LdapServerConfig)
async def get_ldap_server(request: Request, user=Depends(get_admin_user)):
    return {
        "label": request.app.state.config.LDAP_SERVER_LABEL,
        "host": request.app.state.config.LDAP_SERVER_HOST,
        "port": request.app.state.config.LDAP_SERVER_PORT,
        "attribute_for_mail": request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL,
        "attribute_for_username": request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME,
        "app_dn": request.app.state.config.LDAP_APP_DN,
        "app_dn_password": request.app.state.config.LDAP_APP_PASSWORD,
        "search_base": request.app.state.config.LDAP_SEARCH_BASE,
        "search_filters": request.app.state.config.LDAP_SEARCH_FILTERS,
        "use_tls": request.app.state.config.LDAP_USE_TLS,
        "certificate_path": request.app.state.config.LDAP_CA_CERT_FILE,
        "validate_cert": request.app.state.config.LDAP_VALIDATE_CERT,
        "ciphers": request.app.state.config.LDAP_CIPHERS,
    }


@router.post("/admin/config/ldap/server")
async def update_ldap_server(
    request: Request, form_data: LdapServerConfig, user=Depends(get_admin_user)
):
    required_fields = [
        "label",
        "host",
        "attribute_for_mail",
        "attribute_for_username",
        "app_dn",
        "app_dn_password",
        "search_base",
    ]
    for key in required_fields:
        value = getattr(form_data, key)
        if not value:
            raise HTTPException(400, detail=f"Required field {key} is empty")

    request.app.state.config.LDAP_SERVER_LABEL = form_data.label
    request.app.state.config.LDAP_SERVER_HOST = form_data.host
    request.app.state.config.LDAP_SERVER_PORT = form_data.port
    request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL = form_data.attribute_for_mail
    request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME = (
        form_data.attribute_for_username
    )
    request.app.state.config.LDAP_APP_DN = form_data.app_dn
    request.app.state.config.LDAP_APP_PASSWORD = form_data.app_dn_password
    request.app.state.config.LDAP_SEARCH_BASE = form_data.search_base
    request.app.state.config.LDAP_SEARCH_FILTERS = form_data.search_filters
    request.app.state.config.LDAP_USE_TLS = form_data.use_tls
    request.app.state.config.LDAP_CA_CERT_FILE = form_data.certificate_path
    request.app.state.config.LDAP_VALIDATE_CERT = form_data.validate_cert
    request.app.state.config.LDAP_CIPHERS = form_data.ciphers

    return {
        "label": request.app.state.config.LDAP_SERVER_LABEL,
        "host": request.app.state.config.LDAP_SERVER_HOST,
        "port": request.app.state.config.LDAP_SERVER_PORT,
        "attribute_for_mail": request.app.state.config.LDAP_ATTRIBUTE_FOR_MAIL,
        "attribute_for_username": request.app.state.config.LDAP_ATTRIBUTE_FOR_USERNAME,
        "app_dn": request.app.state.config.LDAP_APP_DN,
        "app_dn_password": request.app.state.config.LDAP_APP_PASSWORD,
        "search_base": request.app.state.config.LDAP_SEARCH_BASE,
        "search_filters": request.app.state.config.LDAP_SEARCH_FILTERS,
        "use_tls": request.app.state.config.LDAP_USE_TLS,
        "certificate_path": request.app.state.config.LDAP_CA_CERT_FILE,
        "validate_cert": request.app.state.config.LDAP_VALIDATE_CERT,
        "ciphers": request.app.state.config.LDAP_CIPHERS,
    }


@router.get("/admin/config/ldap")
async def get_ldap_config(request: Request, user=Depends(get_admin_user)):
    return {"ENABLE_LDAP": request.app.state.config.ENABLE_LDAP}


class LdapConfigForm(BaseModel):
    enable_ldap: Optional[bool] = None


@router.post("/admin/config/ldap")
async def update_ldap_config(
    request: Request, form_data: LdapConfigForm, user=Depends(get_admin_user)
):
    request.app.state.config.ENABLE_LDAP = form_data.enable_ldap
    return {"ENABLE_LDAP": request.app.state.config.ENABLE_LDAP}


############################
# API Key
############################


# create api key
@router.post("/api_key", response_model=ApiKey)
async def generate_api_key(
    request: Request, user=Depends(get_current_user), db: Session = Depends(get_session)
):
    if not request.app.state.config.ENABLE_API_KEYS or not has_permission(
        user.id, "features.api_keys", request.app.state.config.USER_PERMISSIONS
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=ERROR_MESSAGES.API_KEY_CREATION_NOT_ALLOWED,
        )

    api_key = create_api_key()
    success = Users.update_user_api_key_by_id(user.id, api_key, db=db)

    if success:
        return {
            "api_key": api_key,
        }
    else:
        raise HTTPException(500, detail=ERROR_MESSAGES.CREATE_API_KEY_ERROR)


# delete api key
@router.delete("/api_key", response_model=bool)
async def delete_api_key(
    user=Depends(get_current_user), db: Session = Depends(get_session)
):
    return Users.delete_user_api_key_by_id(user.id, db=db)


# get api key
@router.get("/api_key", response_model=ApiKey)
async def get_api_key(
    user=Depends(get_current_user), db: Session = Depends(get_session)
):
    api_key = Users.get_user_api_key_by_id(user.id, db=db)
    if api_key:
        return {
            "api_key": api_key,
        }
    else:
        raise HTTPException(404, detail=ERROR_MESSAGES.API_KEY_NOT_FOUND)

############################
# Verification & Reset Password (NEW)
############################

class VerifyEmailForm(BaseModel):
    email: str
    code: str

@router.post("/verify")
async def verify_email(
    request: Request, 
    form_data: VerifyEmailForm,
    db: Session = Depends(get_session)
):
    redis_client = get_redis_client()
    key = f"verification:{form_data.email.lower()}"
    stored_code = redis_client.get(key)
    
    if stored_code is None:
        raise HTTPException(status_code=400, detail="验证码已过期或不存在")
    
    if isinstance(stored_code, bytes):
         stored_code = stored_code.decode('utf-8')

    if stored_code != form_data.code:
        raise HTTPException(status_code=400, detail="验证码错误")

    user = Users.get_user_by_email(form_data.email.lower(), db=db)
    if not user:
        raise HTTPException(404, detail="User not found.")

    default_role = request.app.state.config.DEFAULT_USER_ROLE
    if default_role == "pending":
        default_role = "user"

    # 验证成功：更新角色
    Users.update_user_role_by_id(user.id, default_role, db=db)
    redis_client.delete(key)
    
    # ---------------- 改动开始 ----------------
    # Sean: 这里我们不再生成 Token，也不自动登录
    # token = create_token(data={"id": user.id}) 
    # user_permissions = ...
    
    return {
        "status": True,
        "detail": "Email verified successfully. Please login."
    }
    # ---------------- 改动结束 ----------------
# --- 找回密码：发送验证码 ---
class ForgotPasswordForm(BaseModel):
    email: str

@router.post("/password/reset/code")
async def forgot_password_code(
    form_data: ForgotPasswordForm,
    db: Session = Depends(get_session)
):
    user = Users.get_user_by_email(form_data.email.lower(), db=db)
    if not user:
        # 为了安全，不要提示“用户不存在”，可以提示“如果邮箱存在则已发送”
        # 但如果是内部系统，直接提示不存在也行。这里我们实诚点。
        raise HTTPException(404, detail="User not found.")

    code = ''.join(random.choices(string.digits, k=6))
    redis_client = get_redis_client()
    # 存入 Redis: reset:{email}，区别于注册的 verification
    redis_client.setex(f"reset:{user.email.lower()}", 600, code)
    
    send_email_code(user.email, code, "Reset Password Code")
    return {"message": "Verification code sent"}

# --- 找回密码：验证并重置 ---
class ResetPasswordForm(BaseModel):
    email: str
    code: str
    new_password: str

@router.post("/password/reset/verify")
async def reset_password_verify(
    form_data: ResetPasswordForm,
    db: Session = Depends(get_session)
):
    redis_client = get_redis_client()
    key = f"reset:{form_data.email.lower()}"
    stored_code = redis_client.get(key)
    
    if not stored_code:
        raise HTTPException(400, detail="Code expired or not found.")
    
    if isinstance(stored_code, bytes):
        stored_code = stored_code.decode('utf-8')
    if stored_code != form_data.code:
        raise HTTPException(400, detail="Invalid code.")
        
    user = Users.get_user_by_email(form_data.email.lower(), db=db)
    if not user:
        raise HTTPException(404, detail="User not found.")
        
    # 重置密码
    try:
        validate_password(form_data.new_password)
        hashed = get_password_hash(form_data.new_password)
        Auths.update_user_password_by_id(user.id, hashed, db=db)
        
        redis_client.delete(key)
        return {"message": "Password reset successfully"}
    except Exception as e:
        raise HTTPException(400, detail=str(e))