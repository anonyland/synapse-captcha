ARG PYTHON_VERSION=3.8

FROM docker.io/python:${PYTHON_VERSION} as base

WORKDIR /app

FROM base as builder

ENV POETRY_VERSION=1.2.2

RUN pip install "poetry==$POETRY_VERSION"
RUN python -m venv /venv
COPY pyproject.toml poetry.lock config.sample.yaml matrix_registration ./
RUN . /venv/bin/activate && poetry install --no-dev --no-root

COPY . .
RUN . /venv/bin/activate && poetry build

# Runtime
FROM base as final

COPY --from=builder /venv /venv
COPY --from=builder /app/dist .

RUN . /venv/bin/activate && pip install *.whl

VOLUME ["/data"]

EXPOSE 5000/tcp

ENTRYPOINT ["/venv/bin/matrix-registration", "--config-path=/data/config.yaml"]