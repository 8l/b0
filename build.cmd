@echo off
rem Build script for b0 on Windows...

set cc=cl
set as=fasm
set cc_flags=/I.\src /I.\include /Zi /Fdb0.pdb /Od /RTCs /GA
set as_flags=
set b0_flags=-i.\src -i.\include -fpe -W -v
set rc=rc

SET cmd=x%1%x
IF %cmd%==xcleanx GOTO :clean
IF %cmd%==xinstallx GOTO :install
IF %cmd%==xuninstallx GOTO :uninstall
IF %cmd%==xi386x GOTO :build_ia32
IF %cmd%==xtestx GOTO :test
IF %cmd%==xaltx GOTO :alt

:build
%cc% %cc_flags% .\src\b0.c
del b0_c.exe
del *.obj /q
ren b0.exe b0_c.exe
del src\b0.inc /q
echo #define WIN64; > src\b0.inc
b0_c %b0_flags% .\src\b0.b0
%as% %as_flags% .\src\b0.asm .\b0_v19.exe
del .\src\b0.asm
b0_v19 %b0_flags% .\src\b0.b0
del b0_v19.exe
del b0_c.exe
del *.ilk /q
del *.pdb /q
%as% %as_flags% .\src\b0.asm .\b0.exe
del src\b0.inc /q
echo #define WIN64;#COMPILER_OPTION RSRC 'src\\rsrc\\b0.res'; > src\b0.inc
b0 %b0_flags% .\src\b0.b0
cd src\rsrc
%rc% /r b0.rc
cd ..\..
%as% %as_flags% .\src\b0.asm .\b0.exe
IF %cmd%==xdllx GOTO :build_dll
goto :end

:build_dll
del src\b0.inc /q
echo #define WIN_DLL;#COMPILER_OPTION DLL 'b0.dll';#COMPILER_OPTION RSRC 'src\\rsrc\\b0.res'; > src\b0.inc
b0 -i.\src -i.\include -W -v .\src\b0.b0
cd src\rsrc
%rc% /r b0.rc
cd ..\..
%as% %as_flags% .\src\b0.asm .\b0.dll
goto :end

:alt
del src\b0.inc /q
echo #define WIN64;#COMPILER_OPTION RSRC 'src\\rsrc\\b0.res'; > src\b0.inc
b0 -i.\src -i.\include -W -v .\src\b0.b0
cd src\rsrc
%rc% /r b0.rc
cd ..\..
%as% %as_flags% .\src\b0.asm .\b0a.exe
goto :end

:test
b0 %b0_flags% .\src\b0.b0
%as% %as_flags% .\src\b0.asm .\b0_v20_0.exe
ren .\src\b0.asm b0_v20_0.asm
b0_v20_0 %b0_flags% .\src\b0.b0
%as% %as_flags% .\src\b0.asm .\b0_v20_1.exe
ren .\src\b0.asm b0_v20_1.asm
b0_v20_1 %b0_flags% .\src\b0.b0
%as% %as_flags% .\src\b0.asm .\b0_v20_2.exe
ren .\src\b0.asm b0_v20_2.asm
echo Compare v0 with v1
fc .\src\b0_v20_0.asm .\src\b0_v20_1.asm
echo Compare v1 with v2
fc .\src\b0_v20_1.asm .\src\b0_v20_2.asm
goto :end

:build_ia32
%cc% %cc_flags% -Di386 .\src\b0.c
del *.obj /q
goto :end

:clean
del *.obj /q
del *.asm /q 
del *.tmp /q
del *.exe /q 
del *.dll /q
del *.ilk /q
del *.pdb /q
del *.tar.bz2 /q 
del *.pdf /q 
del *.ps /q 
del *.*~ /q
del *.msi /q
del .\examples\*.asm /q 
del .\examples\*.obj /q
del .\src\*.asm /q
del .\src\*.*~ /q
goto :end

:install
IF EXIST "%PROGRAMFILES%\b0" GOTO :i1
mkdir "%PROGRAMFILES%\b0"
:i1
xcopy b0.exe "%PROGRAMFILES%\b0" /y /q
IF EXIST "%PROGRAMFILES%\b0\include" GOTO :i2
mkdir "%PROGRAMFILES%\b0\include"
:i2
xcopy .\include\stdlib.b0 "%PROGRAMFILES%\b0\include" /y /q
xcopy .\include\stdlib_unicode.b0 "%PROGRAMFILES%\b0\include" /y /q
regedit /s src\rsrc\b0_ext.reg
@echo.
@echo Please add %PROGRAMFILES%\b0 to PATH environment variable
@echo Please set environment variable BO_INCLUDE=%PROGRAMFILES%\b0\include
@echo. 
GOTO :end

:uninstall
IF NOT EXIST "%PROGRAMFILES%\b0" GOTO :end
rmdir "%PROGRAMFILES%\b0" /s /q

:end
