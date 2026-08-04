@echo off
rem =============================================================================
rem build.bat - 一键编译 sandbox_demo M0 版本
rem   * 生成到 build_m0/ 目录，避免和旧 build/ 冲突
rem   * 默认 Debug，方便下断点看效果
rem =============================================================================

setlocal
set BUILD_DIR=build_m0
set CFG=Debug

if not exist %BUILD_DIR% (
    cmake -S . -B %BUILD_DIR% -G "Visual Studio 17 2022" -A x64
    if errorlevel 1 goto fail
)

cmake --build %BUILD_DIR% --config %CFG%
if errorlevel 1 goto fail

echo.
echo [OK] Built: %BUILD_DIR%\%CFG%\m0_demo.exe
exit /b 0

:fail
echo [FAIL] Build failed.
exit /b 1
