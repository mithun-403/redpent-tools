# redpent-tools — Kali-based image with the full SOP toolset preinstalled.
# Build:  docker build -t redpent-tools .
# Run as the HTTP MCP service (auto-generates + prints an API key on first start):
#   docker run -d --name redpent-tools -p 8971:8971 \
#     -v "$PWD/scope.yaml:/app/scope.yaml:ro" \
#     -v redpent-data:/data -v "$PWD/evidence:/app/evidence" redpent-tools
#   docker logs redpent-tools    # <- the generated API key is printed here
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/root/go/bin:${PATH}" \
    REDPENT_SCOPE_FILE=/app/scope.yaml \
    REDPENT_EVIDENCE_DIR=/app/evidence \
    REDPENT_WORDLISTS_DIR=/app/wordlists

# System + CLI recon tools (SOP Appendix S) ----------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      whois dnsutils curl openssl ca-certificates \
      nmap masscan nikto sslscan \
      sqlmap commix \
      golang-go git \
      theharvester wafw00f \
    && rm -rf /var/lib/apt/lists/*

# Go-based tools from ProjectDiscovery / tomnomnom / ffuf ---------------------
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/ffuf/ffuf/v2@latest

WORKDIR /app
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt
COPY . /app
RUN pip3 install --no-cache-dir --break-system-packages -e . || true \
 && chmod +x /app/docker-entrypoint.sh

ENV REDPENT_HTTP_PORT=8971 REDPENT_API_KEY_FILE=/data/redpent-api-key
EXPOSE 8971
VOLUME ["/data"]

# Entrypoint auto-generates + persists + prints the API key, then serves HTTP with auth.
ENTRYPOINT ["/app/docker-entrypoint.sh"]
