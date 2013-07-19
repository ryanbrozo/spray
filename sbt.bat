set SCRIPT_DIR=%~dp0
java -XX:+CMSClassUnloadingEnabled -Xss2m -XX:PermSize=64M -XX:MaxPermSize=512M -Xms256M -Xmx512M -jar "%SCRIPT_DIR%\sbt-launch.jar" %*
