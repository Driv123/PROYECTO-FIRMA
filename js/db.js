/**
 * ═══════════════════════════════════════════════════════════════════════
 *  DB  —  Capa de datos sobre Supabase (con Realtime)
 * ═══════════════════════════════════════════════════════════════════════
 *  Reemplaza al antiguo Store (localStorage). Usa el cliente oficial
 *  @supabase/supabase-js cargado por CDN en cada página.
 *
 *  Catálogo de productos y estados se mantienen aquí (no necesitan BD).
 * ═══════════════════════════════════════════════════════════════════════
 */

// ── CATÁLOGO DE REFRESCOS ─────────────────────────────────────────────────
const CATALOGO = [
  { id: 'coca-600',     nombre: 'Coca-Cola 600 ml',      paquete: 'Paquete 24 pzas', precio: 312, color: '#e3120b', emoji: '🥤' },
  { id: 'coca-2l',      nombre: 'Coca-Cola 2 L',         paquete: 'Paquete 8 pzas',  precio: 280, color: '#c1100a', emoji: '🍾' },
  { id: 'cocalight-600',nombre: 'Coca-Cola Light 600 ml',paquete: 'Paquete 24 pzas', precio: 320, color: '#222222', emoji: '🥤' },
  { id: 'jarritos-mand',nombre: 'Jarritos Mandarina',    paquete: 'Paquete 24 pzas', precio: 245, color: '#f5a623', emoji: '🍊' },
  { id: 'jarritos-tam', nombre: 'Jarritos Tamarindo',    paquete: 'Paquete 24 pzas', precio: 245, color: '#a0522d', emoji: '🟤' },
  { id: 'jarritos-lim', nombre: 'Jarritos Limón',        paquete: 'Paquete 24 pzas', precio: 245, color: '#7cb342', emoji: '🟢' },
  { id: 'sprite-600',   nombre: 'Sprite 600 ml',         paquete: 'Paquete 24 pzas', precio: 300, color: '#16a34a', emoji: '🥤' },
  { id: 'fanta-naranja',nombre: 'Fanta Naranja 600 ml',  paquete: 'Paquete 24 pzas', precio: 298, color: '#f97316', emoji: '🍊' },
  { id: 'fanta-uva',    nombre: 'Fanta Uva 600 ml',      paquete: 'Paquete 24 pzas', precio: 298, color: '#7c3aed', emoji: '🍇' },
  { id: 'manzanita',    nombre: 'Manzanita Sol 600 ml',  paquete: 'Paquete 24 pzas', precio: 290, color: '#16a34a', emoji: '🍏' },
  { id: 'fresca',       nombre: 'Fresca Toronja 600 ml', paquete: 'Paquete 24 pzas', precio: 295, color: '#eab308', emoji: '🍋' },
  { id: 'pepsi-600',    nombre: 'Pepsi 600 ml',          paquete: 'Paquete 24 pzas', precio: 285, color: '#1d4ed8', emoji: '🥤' },
  { id: 'sevenup-600',  nombre: '7Up 600 ml',            paquete: 'Paquete 24 pzas', precio: 285, color: '#22c55e', emoji: '🟢' },
  { id: 'mundet-600',   nombre: 'Sidral Mundet 600 ml',  paquete: 'Paquete 24 pzas', precio: 288, color: '#dc2626', emoji: '🍎' },
];
function catalogoPorId(id) { return CATALOGO.find(p => p.id === id) || null; }
function formatoMXN(n) { return new Intl.NumberFormat('es-MX', { style: 'currency', currency: 'MXN' }).format(n || 0); }

const ESTADOS = {
  firmado_cliente:  { label: 'Firmado por cliente',   desc: 'Esperando verificación y aval del vendedor', color: '#3873ff', bg: '#edf2ff', icon: 'ti-user-check' },
  firmado_vendedor: { label: 'Avalado por vendedor',  desc: 'Esperando verificación final del almacén',   color: '#f07820', bg: '#fff3e8', icon: 'ti-briefcase' },
  entregado:        { label: 'Verificado y entregado',desc: 'Ambas firmas válidas — pedido entregado',     color: '#1eaa5a', bg: '#eafaf0', icon: 'ti-circle-check' },
  rechazado:        { label: 'Rechazado',             desc: 'Una firma no es válida — pedido rechazado',   color: '#e24b4a', bg: '#fff0f0', icon: 'ti-circle-x' },
};

// ── Cliente Supabase ───────────────────────────────────────────────────────
let _sb = null;
function sb() {
  if (_sb) return _sb;
  if (typeof supabase === 'undefined') {
    throw new Error('No se cargó la librería de Supabase. Revisa la etiqueta <script> del CDN.');
  }
  _sb = supabase.createClient(SUPABASE_CONFIG.url, SUPABASE_CONFIG.anonKey);
  return _sb;
}

// ═══════════════════════════════════════════════════════════════════════════
//  DB — operaciones
// ═══════════════════════════════════════════════════════════════════════════
const DB = {

  // ── USUARIOS ──────────────────────────────────────────────────────────
  async crearUsuario(u) {
    const { data, error } = await sb().from('usuarios').insert({
      username:        u.username,
      nombre:          u.nombre,
      email:           u.email,
      password_hash:   u.passwordHash,
      password_salt:   u.passwordSalt,
      rol:             u.rol,
      llave_publica:   u.llavePublicaB64,
      llave_privada_cifrada: u.llavePrivadaCifrada,
      ecdh_publica:          u.ecdhPublicaB64 || null,
      ecdh_privada_cifrada:  u.ecdhPrivadaCifrada || null,
      tarjeta_cifrada: u.tarjetaCifrada,
      rfc_cifrado:     u.rfcCifrado,
      direccion:       u.direccion,
    }).select().single();
    if (error) throw error;
    return data;
  },

  // Devuelve el primer almacén registrado (su pública ECDH sirve para cifrar)
  async getAlmacen() {
    const { data, error } = await sb().from('usuarios').select('*').eq('rol', 'almacen').limit(1);
    if (error) throw error;
    return (data && data[0]) || null;
  },

  async getUsuario(username) {
    const { data, error } = await sb().from('usuarios').select('*').eq('username', username).maybeSingle();
    if (error) throw error;
    return data;
  },

  async getUsuarioPorRol(rol) {
    const { data, error } = await sb().from('usuarios').select('*').eq('rol', rol);
    if (error) throw error;
    return data || [];
  },

  async getTodosUsuarios() {
    const { data, error } = await sb().from('usuarios').select('*');
    if (error) throw error;
    return data || [];
  },

  async existeUsuario(username) {
    const u = await this.getUsuario(username);
    return !!u;
  },

  // ── PEDIDOS ───────────────────────────────────────────────────────────
  async nextFolio() {
    const { data, error } = await sb().from('pedidos').select('folio').order('id', { ascending: false }).limit(1);
    if (error) throw error;
    let max = 0;
    if (data && data[0]) {
      const m = /PED-(\d+)/.exec(data[0].folio || '');
      if (m) max = parseInt(m[1], 10);
    }
    return 'PED-' + String(max + 1).padStart(3, '0');
  },

  async crearPedido(p) {
    const { data, error } = await sb().from('pedidos').insert({
      folio:            p.folio,
      cliente_username: p.clienteUsername,
      cliente_nombre:   p.clienteNombre,
      contenido_pedido: p.contenidoPedido,
      items:            p.items,
      importe:          p.importe,
      fecha_entrega:    p.fechaEntrega,
      firma_cliente:    p.firmaCliente,
      firma_vendedor:   null,
      estado:           'firmado_cliente',
    }).select().single();
    if (error) throw error;
    return data;
  },

  async getPedidos() {
    const { data, error } = await sb().from('pedidos').select('*').order('id', { ascending: false });
    if (error) throw error;
    return data || [];
  },

  async getPedido(folio) {
    const { data, error } = await sb().from('pedidos').select('*').eq('folio', folio).maybeSingle();
    if (error) throw error;
    return data;
  },

  async actualizarPedido(folio, patch) {
    patch.actualizado_en = new Date().toISOString();
    const { data, error } = await sb().from('pedidos').update(patch).eq('folio', folio).select().single();
    if (error) throw error;
    return data;
  },

  // ── REALTIME ──────────────────────────────────────────────────────────
  // Llama a `cb` cada vez que cambie cualquier pedido (insert/update/delete).
  suscribirPedidos(cb) {
    return sb()
      .channel('pedidos-rt')
      .on('postgres_changes', { event: '*', schema: 'public', table: 'pedidos' }, payload => cb(payload))
      .subscribe();
  },
};

// ── Helpers de mapeo (BD snake_case -> objeto camelCase usado en la UI) ─────
function mapPedido(row) {
  if (!row) return null;
  return {
    id:               row.folio,
    folio:            row.folio,
    clienteUsername:  row.cliente_username,
    clienteNombre:    row.cliente_nombre,
    contenidoPedido:  row.contenido_pedido,
    items:            row.items,
    importe:          row.importe,
    fechaEntrega:     row.fecha_entrega,
    firmaCliente:     row.firma_cliente,
    firmaVendedor:    row.firma_vendedor,
    vendedorUsername: row.vendedor_username,
    vendedorNombre:   row.vendedor_nombre,
    estado:           row.estado,
    motivoRechazo:    row.motivo_rechazo,
    intervenido:      row.intervenido,
    creadoEn:         row.creado_en,
  };
}
