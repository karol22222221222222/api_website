import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Cargar variables de entorno
load_dotenv()

# --- Configuración de la App ---
app = FastAPI(
    title="Mi Inventario API",
    description="API para gestionar el inventario y la autenticación de usuarios.",
    version="1.0.0"
)

# --- Middleware de CORS ---
# Permite que el frontend de React se comunique con esta API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Se puede restringir a la URL del frontend en producción
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Variables de Entorno y Secretos ---
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key_for_development")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# --- Modelos de Datos (Pydantic) ---
class UserCreate(BaseModel):
    email: str
    password: str
    businessName: str

class UserLogin(BaseModel):
    email: str
    password: str

class TokenData(BaseModel):
    email: str | None = None

class ProductCreate(BaseModel):
    name: str
    quantity: int
    price: float
    supplier: str | None = None
    category: str | None = None
    minStock: int = 5
    userId: int

class ProductUpdate(BaseModel):
    name: str
    quantity: int
    price: float
    supplier: str | None = None
    category: str | None = None
    minStock: int

# --- Conexión a la Base de Datos ---
def get_oltp_db_connection():
    conn = psycopg2.connect(
        dbname="oltp",
        user="superu",
        password="password_oltp",
        host="localhost",
        port="5434"
    )
    return conn

def get_olap_db_connection():
    conn = psycopg2.connect(
        dbname="olap",
        user="superu",
        password="password_olap",
        host="localhost",
        port="5433"
    )
    return conn

# --- Funciones de Utilidad de Autenticación ---
def verify_password(plain_password, hashed_password):
    return bcrypt.hashpw.checkpw(plain_password, hashed_password)

def get_password_hash(password):
    salt = bcrypt.gensalt()
    password = b'invulnerablepassword' 
    return bcrypt.hashpw(password,salt)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Rutas de la API ---

@app.get("/api", tags=["Root"])
def read_root():
    return {"message": "Bienvenido a la API de Mi Inventario"}

# --- Endpoints de Autenticación ---

@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED, tags=["Autenticación"])
def register_user(user: UserCreate):
    # Lógica para registrar al usuario en la tabla 'usuarios' de la BD OLTP
    # (La tabla se creará más adelante)
    hashed_password = get_password_hash(user.password)
    conn = None
    try:
        conn = get_oltp_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO usuarios (email, password_hash, nombre_negocio) VALUES (%s, %s, %s) RETURNING id",
            (user.email, hashed_password, user.businessName)
        )
        new_user_id = cursor.fetchone()[0]
        conn.commit()
        cursor.close()
        return {"message": "Usuario creado exitosamente", "userId": new_user_id}
    except psycopg2.IntegrityError:
        raise HTTPException(status_code=400, detail="El correo ya está registrado")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error del servidor: {e}")
    finally:
        if conn:
            conn.close()

@app.post("/api/auth/login", tags=["Autenticación"])
def login_for_access_token(form_data: UserLogin):
    # Lógica para verificar al usuario y devolver un token JWT
    conn = None
    try:
        conn = get_oltp_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM usuarios WHERE email = %s", (form_data.email,))
        user = cursor.fetchone()
        cursor.close()

        if not user or not verify_password(form_data.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales incorrectas",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["email"], "userId": user["id"]}, expires_delta=access_token_expires
        )

        return {
            "token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "email": user["email"],
                "businessName": user["nombre_negocio"]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error del servidor: {e}")
    finally:
        if conn:
            conn.close()

# --- Endpoints de Productos --- 

@app.get("/api/products/{user_id}", tags=["Productos"])
def get_products_by_user(user_id: int):
    # En esta versión, combinamos información de la base de datos OLAP (para stock)
    # y OLTP (para el maestro de productos).
    # La vinculación real por usuario se omite por simplicidad en este paso.
    olap_conn = None
    try:
        olap_conn = get_olap_db_connection()
        cursor = olap_conn.cursor(cursor_factory=RealDictCursor)
        
        # Usamos COALESCE para manejar productos que podrían no tener aún un precio sugerido o categoría.
        query = """
        SELECT 
            p.producto_id as id,
            pm.nombre_producto as name,
            p.stock_actual as quantity,
            COALESCE(p.precio_sugerido_venta, 0.0) as price,
            p.proveedor_principal as supplier,
            COALESCE(p.categoria, 'Sin Categoría') as category,
            p.stock_minimo as minStock
        FROM productos p
        JOIN productos_maestro pm ON p.producto_id = pm.producto_id;
        """
        
        cursor.execute(query)
        products = cursor.fetchall()
        cursor.close()

        # Añadimos el userId que el frontend espera
        for p in products:
            p['userId'] = user_id

        return products
    except Exception as e:
        # Si la tabla 'productos' en OLAP no existe, devolvemos una lista vacía.
        if "relation \"productos\" does not exist" in str(e):
            return []
        raise HTTPException(status_code=500, detail=f"Error del servidor al consultar OLAP: {e}")
    finally:
        if olap_conn:
            olap_conn.close()


@app.post("/api/products", status_code=status.HTTP_201_CREATED, tags=["Productos"])
def create_product(product: ProductCreate):
    # Este proceso es complejo y requiere transacciones en la BD OLTP.
    # 1. Crear el producto en 'productos_maestro'.
    # 2. Crear una transacción de 'ENTRADA_MERCANCIA'.
    # 3. Crear un item en 'items_transaccion' para registrar el costo y cantidad inicial.
    
    oltp_conn = get_oltp_db_connection()
    cursor = oltp_conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Paso 1: Crear el producto en el maestro
        cursor.execute(
            "INSERT INTO productos_maestro (producto_id, nombre_producto) VALUES (%s, %s) ON CONFLICT (producto_id) DO NOTHING RETURNING producto_id",
            (product.name.lower().replace(" ", "-"), product.name)
        )
        result = cursor.fetchone()
        # Si el producto ya existe, no hacemos nada y procedemos.
        producto_id = result['producto_id'] if result else product.name.lower().replace(" ", "-")

        # Paso 2: Crear la transacción de entrada
        cursor.execute(
            "INSERT INTO transacciones (tipo_transaccion, notas) VALUES ('ENTRADA_MERCANCIA', %s) RETURNING transaccion_id",
            (f"Entrada inicial para {product.name}",)
        )
        transaccion_id = cursor.fetchone()['transaccion_id']

        # Paso 3: Crear el item de la transacción (el producto que entró)
        # Asumimos que el 'price' del frontend es el costo de compra inicial.
        cursor.execute(
            """
            INSERT INTO items_transaccion (transaccion_id, producto_id, cantidad, costo_unitario_compra)
            VALUES (%s, %s, %s, %s) RETURNING item_id
            """,
            (transaccion_id, producto_id, product.quantity, product.price)
        )
        item_id = cursor.fetchone()['item_id']

        oltp_conn.commit()

        # El ETL se encargaría de mover esto a OLAP. Por ahora, devolvemos lo que el frontend necesita.
        new_product_response = {
            "id": producto_id,
            "name": product.name,
            "quantity": product.quantity,
            "price": product.price,
            "supplier": product.supplier,
            "category": product.category,
            "minStock": product.minStock,
            "userId": product.userId,
            "createdAt": datetime.utcnow().isoformat()
        }
        
        return new_product_response

    except Exception as e:
        oltp_conn.rollback()
        raise HTTPException(status_code=500, detail=f"Error del servidor en OLTP: {e}")
    finally:
        cursor.close()
        oltp_conn.close()


# --- Placeholder para otros endpoints ---
# PUT /api/products/{id}
# DELETE /api/products/{id}
# GET /api/categories/{userId}
# GET /api/reportes/...

if __name__ == "__main__":
    import uvicorn
    # Antes de iniciar, nos aseguramos de que la tabla de usuarios exista.
    conn = get_oltp_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            nombre_negocio VARCHAR(255),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()
    
    print("Tabla 'usuarios' verificada/creada en la base de datos OLTP.")
    print("Iniciando servidor en http://localhost:8000")
    
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
