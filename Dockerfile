FROM python:3.6

RUN pip3 install pipenv pytest

WORKDIR /app

COPY Pipfile* ./
RUN pipenv install --system --deploy

COPY . .

