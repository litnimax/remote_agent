FROM alpine:3.8

WORKDIR /srv/agent/

RUN apk add --no-cache python2 py2-gevent py2-pip py2-requests tini

COPY requirements.txt /srv/agent/
RUN pip install -r requirements.txt

COPY agent.crt agent.key __init__.py gevent_agent.py /srv/agent/

CMD tini -- python2 ./gevent_agent.py

