FROM ubuntu:17.10

RUN apt-get update
RUN apt-get install -y python3.7 python3-pip docker

CMD python3 --version
COPY r2c_lib-*-py3-none-any.whl .
COPY dist/*-py3-none-any.whl .
RUN pip3 install r2c_lib-*-py3-none-any.whl r2c_cli-*-py3-none-any.whl
ENV GIT_PYTHON_REFRESH quiet
ENV LC_ALL C.UTF-8
RUN r2c --help
ARG analyzer_name=ubuntu-test
RUN r2c init --analyzer-name $analyzer_name --author-name tester --author-email tester --run-on commit --output-type json
RUN ls
WORKDIR $analyzer_name
RUN ls
RUN r2c run --no-login -c .