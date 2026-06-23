-- ═══════════════════════════════════════════════════════════════════════
--  VerifySign — Esquema de base de datos para Supabase
-- ═══════════════════════════════════════════════════════════════════════
--  Ejecuta este script completo en:
--  Supabase Dashboard -> SQL Editor -> New query -> Run
-- ═══════════════════════════════════════════════════════════════════════

-- ── Limpieza (por si re-ejecutas) ──────────────────────────────────────
drop table if exists pedidos cascade;
drop table if exists usuarios cascade;

-- ═══════════════════════════════════════════════════════════════════════
--  TABLA: usuarios
-- ═══════════════════════════════════════════════════════════════════════
--  Guarda el registro de cada usuario.
--  - llave_publica: en claro (es pública por diseño, sirve para verificar firmas)
--  - tarjeta_cifrada y rfc_cifrado: cifrados con ECIES (ECDH P-256 + AES-GCM).
--    En la BD solo se ven como texto ilegible (iv + ciphertext + ephemeral key).
--  - direccion: en claro (el usuario pidió que NO se cifre).
-- ═══════════════════════════════════════════════════════════════════════
create table usuarios (
  id            bigint generated always as identity primary key,
  username      text unique not null,
  nombre        text not null,
  email         text,
  -- Contraseña: hash SHA-256 con salt PROPIO (solo para login)
  password_hash text not null,
  password_salt text not null,
  rol           text not null check (rol in ('cliente','vendedor','almacen')),

  -- Llave pública ECDSA (SPKI Base64) — PÚBLICA, en claro (verifica firmas)
  llave_publica text not null,
  -- Llave privada ECDSA cifrada con la contraseña (PBKDF2+AES-GCM): {salt,iv,ct}
  llave_privada_cifrada jsonb not null,

  -- Solo el ALMACÉN tiene par ECDH para descifrar datos sensibles:
  --   ecdh_publica         : llave pública ECDH (hacia ella se cifra) - en claro
  --   ecdh_privada_cifrada : llave privada ECDH cifrada con su contraseña
  ecdh_publica         text,
  ecdh_privada_cifrada jsonb,

  -- Datos sensibles CIFRADOS hacia la pública ECDH del almacén ({iv,ct,epk})
  tarjeta_cifrada jsonb,
  rfc_cifrado     jsonb,

  -- Dato NO sensible, en claro
  direccion     text,

  creado_en     timestamptz default now()
);

-- ═══════════════════════════════════════════════════════════════════════
--  TABLA: pedidos
-- ═══════════════════════════════════════════════════════════════════════
--  contenido_pedido: el STRING EXACTO que se firmó (no tocar formato).
--  firma_cliente / firma_vendedor: objetos JSON {firmaB64, sha256Contenido, ...}
-- ═══════════════════════════════════════════════════════════════════════
create table pedidos (
  id               bigint generated always as identity primary key,
  folio            text unique not null,

  cliente_username text not null,
  cliente_nombre   text not null,

  -- Documento firmado (string crudo, idéntico para todas las partes)
  contenido_pedido text not null,

  -- Resumen visible para la lista (NO sensible)
  items            jsonb not null,
  importe          numeric not null,
  fecha_entrega    text,

  -- Firmas
  firma_cliente    jsonb not null,
  firma_vendedor   jsonb,
  vendedor_username text,
  vendedor_nombre   text,

  estado           text not null default 'firmado_cliente'
                   check (estado in ('firmado_cliente','firmado_vendedor','entregado','rechazado')),

  motivo_rechazo   text,

  -- Marca si el sniffer lo intervino (para la demo)
  intervenido      boolean default false,

  creado_en        timestamptz default now(),
  actualizado_en   timestamptz default now()
);

-- ── Índices útiles ─────────────────────────────────────────────────────
create index idx_pedidos_estado on pedidos(estado);
create index idx_pedidos_cliente on pedidos(cliente_username);

-- ═══════════════════════════════════════════════════════════════════════
--  REALTIME — para que los cambios del sniffer se vean en vivo
-- ═══════════════════════════════════════════════════════════════════════
alter publication supabase_realtime add table pedidos;
alter publication supabase_realtime add table usuarios;

-- ═══════════════════════════════════════════════════════════════════════
--  ROW LEVEL SECURITY (RLS)
-- ═══════════════════════════════════════════════════════════════════════
--  IMPORTANTE: Esta es una DEMO académica que usa la 'anon key' sin
--  Supabase Auth. Para que la demo funcione (y para que el sniffer pueda
--  intentar inyecciones, que es justo lo que quieres mostrar), abrimos
--  políticas permisivas. En producción real esto NO se hace así: se usaría
--  Supabase Auth + políticas estrictas por usuario.
-- ═══════════════════════════════════════════════════════════════════════
alter table usuarios enable row level security;
alter table pedidos  enable row level security;

-- Políticas abiertas (solo para la demo)
create policy "demo_usuarios_all" on usuarios for all using (true) with check (true);
create policy "demo_pedidos_all"  on pedidos  for all using (true) with check (true);

-- ── Verificación ───────────────────────────────────────────────────────
select 'Tablas creadas correctamente ✓' as resultado;
