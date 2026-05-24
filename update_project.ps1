# update_project.ps1
# ============================================================
# Aplica todos los cambios de nomenclatura al Proyecto 1
# Ejecutar desde: C:\Proyectos\Log Analyzer\log-analyzer\
# ============================================================

Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  Log Analyzer - Actualizacion de nomenclatura"
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# --- Paso 1: Verificar ubicacion correcta ---
if (-not (Test-Path "run_etl.py")) {
    Write-Host "ERROR: Ejecuta desde la carpeta log-analyzer\" -ForegroundColor Red
    exit 1
}
Write-Host "[1/6] Ubicacion verificada: OK" -ForegroundColor Green

# --- Paso 2: Verificar ai_engine.py ---
Write-Host "[2/6] Verificando ai_engine.py..." -ForegroundColor Cyan
if (Test-Path "core\ai_engine.py") {
    Write-Host "  core\ai_engine.py encontrado: OK" -ForegroundColor Green
} else {
    Write-Host "  ERROR: Copia core\ai_engine.py del ZIP primero" -ForegroundColor Red
    exit 1
}

# --- Paso 3: Eliminar claude_client.py ---
Write-Host "[3/6] Eliminando claude_client.py..." -ForegroundColor Cyan
if (Test-Path "core\claude_client.py") {
    Remove-Item "core\claude_client.py" -Force
    Write-Host "  Eliminado: OK" -ForegroundColor Green
} else {
    Write-Host "  No existe: OK" -ForegroundColor Green
}

# --- Paso 4: Actualizar .env ---
Write-Host "[4/6] Actualizando .env..." -ForegroundColor Cyan
if (Test-Path ".env") {
    $envContent = Get-Content ".env" -Raw
    if ($envContent -match "ANTHROPIC_API_KEY") {
        $envContent = $envContent -replace "ANTHROPIC_API_KEY", "AI_ENGINE_KEY"
        Set-Content ".env" $envContent -NoNewline
        Write-Host "  ANTHROPIC_API_KEY -> AI_ENGINE_KEY: OK" -ForegroundColor Green
    } else {
        Write-Host "  .env ya actualizado: OK" -ForegroundColor Green
    }
} else {
    Write-Host "  .env no existe - crea uno desde .env.example" -ForegroundColor Yellow
}

# --- Paso 5: Migrar base de datos ---
Write-Host "[5/6] Migrando base de datos..." -ForegroundColor Cyan
python migrate_db.py

# --- Paso 6: Verificar motor de analisis ---
Write-Host "[6/6] Verificando motor de analisis..." -ForegroundColor Cyan
python -c "import sys; sys.path.insert(0,'.'); from core.ai_engine import SecurityAnalyst; a=SecurityAnalyst(); print('  Motor OK - modo:', a.mode)"

Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  Actualizacion completada"
Write-Host ""
Write-Host "  Proximos pasos:"
Write-Host "    python run_etl.py"
Write-Host "    python core/detector.py"
Write-Host "    python core/ai_engine.py --limit 20"
Write-Host "    streamlit run app.py"
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""
