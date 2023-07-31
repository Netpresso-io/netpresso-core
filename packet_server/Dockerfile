FROM python:3.11.2-alpine3.17

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

EXPOSE 5000

COPY . .

CMD [ "flask", "--app", "packet_server.py", "run","--host=0.0.0.0", "--port", "5000"]