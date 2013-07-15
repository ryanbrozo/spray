java -XX:PermSize=64M -XX:MaxPermSize=512M -Xmx1024M -Xss2M -XX:+CMSClassUnloadingEnabled -jar `dirname $0`/sbt-launch.jar "$@"
