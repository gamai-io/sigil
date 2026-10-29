FROM python:3.12-slim
COPY dist/sigil_profile-0.22.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir /tmp/sigil_profile-0.22.0-py3-none-any.whl
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65534:65534
