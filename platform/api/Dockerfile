FROM python:3.13-slim

WORKDIR /app

COPY platform/api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY platform/api/app /app/app
COPY platform/ui /app/ui
COPY platform/api/alembic /app/alembic
COPY platform/api/alembic.ini /app/alembic.ini

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
