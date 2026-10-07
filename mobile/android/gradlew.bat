@echo off
setlocal EnableDelayedExpansion

set APP_HOME=%~dp0

set DEFAULT_JVM_OPTS=%DEFAULT_JVM_OPTS% -Xmx2048m -XX:MaxMetaspaceSize=512m
set GRADLE_OPTS=%GRADLE_OPTS% %DEFAULT_JVM_OPTS%

set JAVA_EXE=

if defined JAVA_HOME (
    set JAVA_EXE=%JAVA_HOME%\bin\java.exe
)

if defined JAVA_EXE (
    if not exist "%JAVA_EXE%" (
        set JAVA_EXE=
    )
)

if not defined JAVA_EXE (
    where java >nul 2>nul
    if !ERRORLEVEL! equ 0 (
        set JAVA_EXE=java
    )
)

if not defined JAVA_EXE (
    echo Error: java command could not be found.
    echo Please install JDK 17 or set JAVA_HOME.
    echo Download from: https://adoptium.net
    exit /b 1
)

set GRADLE_EXE=%APP_HOME%gradle\wrapper\gradle-wrapper.jar

if not exist "%GRADLE_EXE%" (
    echo.
    echo The Gradle wrapper was not found.
    echo Expected: %GRADLE_EXE%
    echo.
    echo Download gradle-wrapper.jar or run:
    echo   gradle wrapper --gradle-version 8.10
    echo.
    echo Alternatively, install Gradle and run:
    echo   gradle assembleRelease
    exit /b 1
)

"%JAVA_EXE%" %GRADLE_OPTS% -classpath "%GRADLE_EXE%" org.gradle.wrapper.GradleWrapperMain %*
