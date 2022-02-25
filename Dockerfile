FROM python:3.10

ENV POETRY_HOME=/poetry
RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/install-poetry.py | python -
ENV PATH=$POETRY_HOME/bin:$PATH
RUN poetry config virtualenvs.create false

RUN mkdir /src
WORKDIR /src



COPY pyproject.toml /src/pyproject.toml
COPY poetry.lock /src/poetry.lock
RUN poetry install --no-root --no-dev

COPY orbi_exporter /src/orbi_exporter
RUN poetry install --no-dev

ENV ORBI_IP 192.168.1.1
ENV ORBI_USERNAME admin
ENV ORBI_PASSWORD password_unset
ENV ORBI_LOG_FORMAT json

# ENTRYPOINT [ "/usr/bin/python", "orbi_exporter" ]
# CMD []