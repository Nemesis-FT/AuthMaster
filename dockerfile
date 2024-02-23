FROM python:3.11-alpine

COPY ./requirements.txt ./requirements.txt

COPY /backend/ /backend/

RUN python3 -m pip install -r requirements.txt

ENTRYPOINT ["python", "-m", "backend"]

CMD []