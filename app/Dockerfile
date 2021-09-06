# i'd like to also gradle shadowJar but it requires files from outside this build context (build.gradle with the jitpack repo)
FROM openjdk:17

WORKDIR /usr/app

COPY /build/libs/authenticator.jar .

ENTRYPOINT [ "java", "-jar", "authenticator.jar" ]