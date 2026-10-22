export const TYPES = ['line', 'arrow', 'polyline', 'curve', 'rectangle', 'circle', 'ellipse', 'freehand', 'icon', 'label', 'note'];
export const LINE_TYPES = ['solid', 'dashed', 'dotted'];
export const COLORS = ['#27634d', '#dc7950', '#4484ad', '#c79e38', '#8d6b9f', '#343c3a'];
export const SYMBOLS = ['tree', 'bench', 'bike', 'walk', 'play', 'home', 'cafe', 'bus', 'light', 'water', 'garden', 'pin', 'fishing', 'book', 'stall', 'ski', 'sport', 'pet', 'picnic', 'skate', 'art', 'music', 'toilet', 'parking', 'fitness', 'chess'];
export const NOTE_COLORS = ['#f1dfa0', '#f0c4bd', '#d8c9eb', '#bcdce8', '#c9dfbd', '#edcfaa'];
export const MAX_SESSION_BYTES = 30_000_000;
export const sessionBytes = session => new TextEncoder().encode(JSON.stringify(session)).length;
export function assertSessionSize(session) {
  if (sessionBytes(session) > MAX_SESSION_BYTES) throw new Error('This session would exceed 30 MB. Use a smaller overlay or start another session.');
}

export function uid() {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export const clone = value => structuredClone(value);
export const escapeHtml = value => String(value).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function newSession(background = { type: 'map' }) {
  return {
    version: 2, assets: {}, overlays: [], activeOverlayId: null, reflection: { enabled: true }, id: uid(), title: background.type === 'image' ? background.name.replace(/\.[^.]+$/, '').slice(0, 150) : 'Untitled neighbourhood',
    createdAt: Date.now(), updatedAt: Date.now(), background, objects: [], views: [], notes: '', noteColor: NOTE_COLORS[0],
    camera: background.type === 'map' ? { center: [59.3267, 14.5239], zoom: 16 } : null,
  };
}

export function validateSession(input, { requireId = false } = {}) {
  const fail = () => { throw new Error('This file is not a valid CITIZEN session.'); };
  const finite = value => typeof value === 'number' && Number.isFinite(value);
  const point = value => Array.isArray(value) && value.length === 2 && value.every(number => finite(number) && Math.abs(number) <= 1e7);
  const camera = value => value && point(value.center) && finite(value.zoom) && value.zoom >= -10 && value.zoom <= 22 &&
    (value.bounds === undefined || (Array.isArray(value.bounds) && value.bounds.length === 2 && value.bounds.every(point)));
  if (!input || ![1, 2].includes(input.version) || typeof input.title !== 'string' || input.title.length > 150 ||
      !Array.isArray(input.objects) || input.objects.length > 10000 || !Array.isArray(input.views) || input.views.length > 200 ||
      typeof input.notes !== 'string' || input.notes.length > 20000) fail();
  if (!input.background || !['map', 'image'].includes(input.background.type)) fail();
  if (input.background.type === 'image') {
    const background = input.background;
    if (typeof background.data !== 'string' || background.data.length > 24e6 || !/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(background.data) ||
        !finite(background.width) || !finite(background.height) || background.width < 1 || background.height < 1 || background.width > 20000 || background.height > 20000 || typeof background.name !== 'string') fail();
  }
  if (input.camera !== null && !camera(input.camera)) fail();
  const overlayIds = new Set();
  if (input.version === 2) {
    if (!input.assets || typeof input.assets !== 'object' || Array.isArray(input.assets) || !Array.isArray(input.overlays) || input.overlays.length > 200 ||
        !input.reflection || typeof input.reflection.enabled !== 'boolean') fail();
    const id = value => typeof value === 'string' && /^[\w-]{1,100}$/.test(value);
    for (const [key, asset] of Object.entries(input.assets)) {
      if (!id(key) || !asset || typeof asset.name !== 'string' || asset.name.length > 500 || typeof asset.source !== 'string' || asset.source.length > 21e6 ||
          !/^data:[\w.+/-]+;base64,[A-Za-z0-9+/=]*$/.test(asset.source) || !Array.isArray(asset.renders) || !asset.renders.length || asset.renders.length > 200) fail();
      for (const render of asset.renders) {
        if (!render || !['raster', 'vector'].includes(render.kind) || typeof render.data !== 'string' || render.data.length > 30e6 ||
            !/^data:image\/(png|jpeg|webp|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(render.data) ||
            !finite(render.width) || !finite(render.height) || render.width <= 0 || render.height <= 0 || render.width > 1e8 || render.height > 1e8) fail();
      }
    }
    for (const layer of input.overlays) {
      const t = layer?.transform;
      if (!layer || !id(layer.id) || !id(layer.assetId) || overlayIds.has(layer.id) || !Object.hasOwn(input.assets, layer.assetId) ||
          !Number.isInteger(layer.renderIndex) || !input.assets[layer.assetId].renders[layer.renderIndex] || typeof layer.name !== 'string' || layer.name.length > 150 ||
          typeof layer.visible !== 'boolean' || !finite(layer.opacity) || layer.opacity < 0 || layer.opacity > 1 ||
          (layer.role !== undefined && !['unspecified', 'context', 'proposal', 'keyplan', 'photo'].includes(layer.role)) ||
          !t || ![t.x, t.y, t.scale, t.rotation].every(finite) || Math.abs(t.x) > 1e9 || Math.abs(t.y) > 1e9 || t.scale <= 0 || t.scale > 1e9 || t.rotation < 0 || t.rotation >= 360) fail();
      overlayIds.add(layer.id);
    }
    if (input.activeOverlayId !== null && !overlayIds.has(input.activeOverlayId)) fail();
    assertSessionSize(input);
  }
  const ids = new Set();
  for (const object of input.objects) {
    if (!object || typeof object.id !== 'string' || object.id.length > 100 || ids.has(object.id) || !TYPES.includes(object.type) ||
        !Array.isArray(object.points) || !object.points.length || object.points.length > 50000 || !object.points.every(point) ||
        !/^#[0-9a-f]{6}$/i.test(object.color) || !finite(object.width) || object.width < 1 || object.width > 16 ||
        !finite(object.opacity) || object.opacity < 0 || object.opacity > 1 || typeof object.fill !== 'boolean' ||
        typeof object.text !== 'string' || object.text.length > 500 || !SYMBOLS.includes(object.symbol)) fail();
    const count = ['icon', 'label', 'note'].includes(object.type) ? 1 : object.type === 'curve' ? (object.curveMode === 'spline' ? null : 3) : ['freehand', 'polyline'].includes(object.type) ? null : 2;
    if (count && object.points.length !== count) fail();
    if (object.hidden !== undefined && typeof object.hidden !== 'boolean') fail();
    if (object.lineType !== undefined && !LINE_TYPES.includes(object.lineType)) fail();
    if (object.description !== undefined && (typeof object.description !== 'string' || object.description.length > 20000)) fail();
    if (object.closed !== undefined && typeof object.closed !== 'boolean') fail();
    if (object.rotation !== undefined && (!finite(object.rotation) || object.rotation < 0 || object.rotation >= 360)) fail();
    if (object.overlayId != null && (input.version !== 2 || !overlayIds.has(object.overlayId))) fail();
    if (object.localScale !== undefined && (!finite(object.localScale) || object.localScale <= 0 || object.localScale > 1e9)) fail();
    if (object.curveMode !== undefined && !['spline', 'quadratic'].includes(object.curveMode)) fail();
    if (object.type === 'curve' && object.curveMode === 'spline' && object.points.length < (object.closed ? 3 : 2)) fail();
    if (object.type === 'polyline' && object.points.length < (object.closed ? 3 : 2)) fail();
    ids.add(object.id);
  }
  const viewIds = new Set();
  for (const view of input.views) {
    if (!view || typeof view.id !== 'string' || view.id.length > 100 || viewIds.has(view.id) || typeof view.name !== 'string' || view.name.length > 100 || !camera(view.camera)) fail();
    viewIds.add(view.id);
  }
  const session = clone(input);
  if (session.noteColor !== undefined && !NOTE_COLORS.includes(session.noteColor)) fail();
  const validId = typeof session.id === 'string' && /^[\w-]{1,100}$/.test(session.id);
  if (requireId && !validId) fail();
  session.id = validId ? session.id : uid();
  session.createdAt = finite(session.createdAt) ? session.createdAt : Date.now();
  session.updatedAt = finite(session.updatedAt) ? session.updatedAt : Date.now();
  return session;
}

// Validation preserves the version and bytes used by archive checksums.
export function upgradeSession(input) {
  const session = validateSession(input);
  if (session.version === 1) Object.assign(session, { version: 2, assets: {}, overlays: [], activeOverlayId: null, reflection: { enabled: true } });
  return session;
}
