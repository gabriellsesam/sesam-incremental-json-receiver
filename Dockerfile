FROM python:3-alpine

LABEL author="Graham Moore graham.moore@sesam.io"
LABEL maintainer="Gabriell Vig gabriell.vig@sesam.io"

COPY ./service /service
WORKDIR /service
RUN pip install --upgrade pip
RUN pip install -r requirements.txt
EXPOSE 5000/tcp
ENTRYPOINT ["python"]
CMD ["incremental-jsonsystem.py"]
