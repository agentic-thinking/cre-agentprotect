FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/agentic-thinking/cre-agentprotect"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.description="CRE-AgentProtect, Microsoft AGT adapter for HookBus. MIT."
LABEL com.agentic-thinking.product="CRE-AgentProtect"
LABEL com.agentic-thinking.tier="community"
LABEL org.opencontainers.image.title="CRE-AgentProtect"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.vendor="Agentic Thinking Limited"
LABEL org.opencontainers.image.documentation="https://github.com/agentic-thinking/cre-agentprotect"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt && rm /tmp/requirements.txt
WORKDIR /app
COPY __init__.py /app/cre_agentprotect.py

RUN groupadd --system --gid 10001 hookbus \
 && useradd  --system --uid 10001 --gid hookbus --home-dir /home/hookbus --create-home --shell /usr/sbin/nologin hookbus \
 && mkdir -p /root/.hookbus \
 && chown -R hookbus:hookbus /app /root/.hookbus
RUN chmod 755 /root

EXPOSE 8878
ENV CRE_AGENTPROTECT_PORT=8878 CRE_AGENTPROTECT_HOST=0.0.0.0

USER hookbus

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8878/healthz', timeout=3); sys.exit(0 if r.status == 200 else 1)" || exit 1

CMD ["python", "-m", "cre_agentprotect"]
