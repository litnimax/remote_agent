FROM alpine:3.8

WORKDIR /app

RUN apk add --no-cache python2 py2-gevent py2-pip tini

COPY requirements.txt /app/
RUN pip install -r requirements.txt

COPY agent.crt agent.key __init__.py gevent_agent.py /app/

CMD tini -- python2 ./gevent_agent.py

