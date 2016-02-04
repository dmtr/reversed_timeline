FROM python:3.5.1
RUN mkdir -p /app/static
RUN mkdir -p /app/reverse_twitter
ADD static /app/static/
ADD reverse_twitter /app/reverse_twitter/
RUN pip install --upgrade pip
WORKDIR /app
RUN pip3 install -r reverse_twitter/requirements.txt
