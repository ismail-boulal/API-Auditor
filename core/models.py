# core/models.py
from dataclasses import dataclass, field
from typing import Any


print("[!] Models reached")
# ceci est une class auth pour definir si une authentification est requise et quel est son schema e.g. BearerAuth APIkeys ...
@dataclass
class Authentication:
    required: bool = False
    schemes: list[str] = field(default_factory=list)

# ceci est une class requestbody qui contient le content type et son schema ainsi que son obligation dans le code 
@dataclass
class RequestBody:
    required: bool = False
    content_types: list[str] = field(default_factory=list)
    schema: dict[str, Any] = field(default_factory=dict)
    properties: dict[str, Any] = field(default_factory=dict)   


@dataclass
class Response:
    status_code: str | None = None
    description: str | None = None
    content_types: list[str] = field(default_factory=list)
    properties: dict[str, Any] = field(default_factory=dict)
    raw: dict = field(default_factory=dict)



# ceci est une class des paramètres de ce endpoint 
@dataclass
class Parameter:
    name: str
    location: str
    required: bool = False
    param_type: str | None = None
    schema: dict[str, Any] = field(default_factory=dict)
    example: Any = None
    is_object_candidate: bool = False

# la class mère de notre Endpoint elle definit tous les champs necaissaire pour les feeder dans notre moteur BOLA BFLA 
@dataclass
class Endpoint:
    path: str
    method: str
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: list[str] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
    request_body: RequestBody | None = None
    authentication: Authentication = field(default_factory=Authentication)
    responses: Response = field(default_factory=Response)
    object_candidates: list[str] = field(default_factory=list)
    is_potential_login_endpoint : bool = False
    
@dataclass
class Account:
    Label: str | None= None
    username: str | None = None
    password: str| None = None
    email: str | None =  None
    token: str | None = None
    role: str | None = None
    cookies: str | None = None
    header: str | None = None

@dataclass
class Finding:
    vulnerability: str
    endpoint:Endpoint
    confidence: str | int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    
    