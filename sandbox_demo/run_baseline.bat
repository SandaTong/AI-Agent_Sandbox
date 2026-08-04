@echo off
rem =============================================================================
rem run_baseline.bat - 直接跑 hello_target（不走沙箱）作为对照组
rem
rem 双击这个 bat 你会看到:
rem   integrity_level = Medium         <- 普通用户级别，能读写你的桌面文件
rem
rem 而双击 run.bat（走沙箱）会看到:
rem   integrity_level = Medium (M0)<- M0 还没降IL，M1 会降到 Low
rem
rem 但 sandboxed 版本还额外套了 Job 限制和 restricted token（privilege 全removed）。
rem =============================================================================

setlocal
set BUILD_DIR=build_m0
set CFG=Debug

echo === Launching hello_target WITHOUT sandbox ===
%BUILD_DIR%\%CFG%\hello_target.exe
echo.
echo === hello_target exit code = %ERRORLEVEL% ===
pause
