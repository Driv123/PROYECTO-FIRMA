const SUPABASE_CONFIG = {
  url:     'https://pfbrykbdsauopvuddkmw.supabase.co',
  anonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBmYnJ5a2Jkc2F1b3B2dWRka213Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzkzMTk5MDQsImV4cCI6MjA5NDg5NTkwNH0.8oBv79-UXI1e26rEcIdBNCP452UPGvzsJ4iafjmdJtw',   // 👈 reemplaza esto
};

// Aviso visible si olvidaste pegar la clave
if (SUPABASE_CONFIG.anonKey === 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBmYnJ5a2Jkc2F1b3B2dWRka213Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzkzMTk5MDQsImV4cCI6MjA5NDg5NTkwNH0.8oBv79-UXI1e26rEcIdBNCP452UPGvzsJ4iafjmdJtw') {
  console.warn('⚠️ Falta tu anon key de Supabase en js/supabase-config.js');
}
