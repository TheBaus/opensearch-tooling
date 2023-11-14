# depending on where you build, you can inject the container registry dynamically
ARG CONTAINER_REGISTRY=dummy_registry
FROM ${CONTAINER_REGISTRY}/python:3.11-slim

# will be used for building and is injected when docker build is run
ARG GIT_NAME=unknown_git_name
ARG GIT_COMMIT=unknown_git_commit

WORKDIR /opt/os-tools
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY scripts/ .

# default is just a one-liner but had to be a "module" due to -m flag in the entrypoint
CMD ["default"]
ENTRYPOINT ["python", "-OOm"]