FROM ubuntu:latest
RUN apt-get -y update
RUN apt-get -y install git
RUN apt-get -y install maven

#RUN mkdir app
WORKDIR /root/app
COPY src/scripts scripts
COPY git_credential_helper.sh git_credential_helper.sh
COPY .github ../.github
COPY owasp-dependency-check /root/owasp-dependency-check
COPY target/GitHub_Api_Accessor-1.0-SNAPSHOT-jar-with-dependencies.jar analyzer.jar
#ENTRYPOINT ["java","-jar","analyzer.jar"]