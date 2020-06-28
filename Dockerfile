FROM python:3-alpine

LABEL author="Graham Moore graham.moore@sesam.io"
LABEL maintainer="Gabriell Vig gabriell.vig@sesam.io"

COPY ./service /service
WORKDIR /service
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

#Deletion of files not allowed by aquascanner.
RUN rm -rf /usr/local/lib/python3.8/site-packages/werkzeug/debug/shared/jquery.js
RUN rm -rf /usr/local/lib/python3.8/ipaddress.py

EXPOSE 5000/tcp
ENTRYPOINT ["python"]
CMD ["incremental-jsonsystem.py"]
