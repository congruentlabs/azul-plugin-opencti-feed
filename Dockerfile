ARG REGISTRY="docker.io/library"
ARG BUILD_IMAGE="python"
ARG BUILD_TAG="3.12-trixie"
ARG BASE_IMAGE="python"
ARG BASE_TAG="3.12-slim-trixie"

FROM $REGISTRY/$BUILD_IMAGE:$BUILD_TAG AS builder
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_DISABLE_PIP_VERSION_CHECK=yes
ARG UV_DEFAULT_INDEX
ARG UV_INDEX_URL
ARG UV_INSECURE_HOST
ARG GIT_BRANCH_NAME
ARG PACKAGE_VERSION=0.0.0
ENV UV_PROJECT_ENVIRONMENT=/usr/local
ENV SETUPTOOLS_SCM_PRETEND_VERSION=$PACKAGE_VERSION
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_AZUL_PLUGIN_OPENCTI_FEED=$PACKAGE_VERSION

COPY debian.txt /tmp/src/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/src/debian.txt | tr "\n" " ") && \
    rm -rf /tmp/src/debian.txt /var/lib/apt/lists/*

COPY ./ /tmp/src
RUN pip install uv
WORKDIR /tmp/src
RUN uv sync --frozen --no-editable
RUN uv pip install --system hatchling hatch-vcs
RUN uv build . --out-dir /tmp/
RUN uv pip uninstall --system azul-plugin-opencti-feed
RUN uv pip install --system --no-deps --find-links /tmp/ azul-plugin-opencti-feed==$(hatchling version)

FROM $REGISTRY/$BASE_IMAGE:$BASE_TAG AS base
ENV DEBIAN_FRONTEND=noninteractive
COPY debian.txt /tmp/src/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/src/debian.txt | tr "\n" " ") && \
    rm -rf /tmp/src/debian.txt /var/lib/apt/lists/*
ARG UID=21000
ARG GID=21000
RUN groupadd -g $GID azul && useradd --create-home --shell /bin/bash -u $UID -g $GID azul
USER azul
COPY --from=builder /usr/local /usr/local

FROM base AS tester
ENV PIP_DISABLE_PIP_VERSION_CHECK=yes
ARG UV_DEFAULT_INDEX
ARG UV_INDEX_URL
ARG UV_INSECURE_HOST
USER root
COPY ./pyproject.toml ./pyproject.toml
RUN uv pip install --system --group dev
USER azul
ENV PATH="/home/azul/.local/bin:$PATH"
COPY --chown=azul ./tests /tmp/tests
RUN pytest -o cache_dir=/tmp/cache --tb=short /tmp/tests
RUN touch /tmp/testingpassed

FROM base AS release
COPY --from=tester /tmp/testingpassed /tmp/
ENTRYPOINT ["azul-plugin-opencti-feed"]
