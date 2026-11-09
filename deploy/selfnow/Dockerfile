# Pinned by digest (the multi-architecture index, so the same line builds on amd64 and arm64). Update it on purpose.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# Standard library only: the server is two files, no pip install.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin selfnow
WORKDIR /app
COPY mockreview/__init__.py /app/mockreview/__init__.py
COPY mockreview/selfnow.py /app/mockreview/selfnow.py
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 MALLOC_ARENA_MAX=2
USER 10001:10001
EXPOSE 8080 8081
# 404 from the owner listener on loopback means the process is up and answering.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["python", "-c", "import urllib.request, urllib.error\ntry:\n    urllib.request.urlopen('http://127.0.0.1:8081/publishes/healthcheck-probe/data/feedback', timeout=3)\nexcept urllib.error.HTTPError as e:\n    raise SystemExit(0 if e.code == 404 else 1)"]
ENTRYPOINT ["python", "-m", "mockreview.selfnow"]
