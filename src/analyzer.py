import re
import requests
import tldextract
import whois
import ssl
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from fuzzywuzzy import fuzz
from datetime import datetime
from fnmatch import fnmatch

DOMINIOS_LEGITIMOS = ["google.com", "facebook.com", "netflix.com", "paypal.com", "insper.edu.br", "github.com"]
DNS_DINAMICO = ["no-ip.com", "duckdns.org", "dyndns.org", "hopto.org"]
EMISSORES_CONFIAVEIS = ["Let's Encrypt", "Google Trust Services", "Amazon", "DigiCert", "Cloudflare", "Sectigo"]

def verificar_url_basica(url):
    resultados = []

    # 1. Substituição de letras por números
    if re.search(r'[a-zA-Z]\d|[0-9][a-zA-Z]', url):
        resultados.append("❌ Substituição de letras por números detectada")

    # 2. Muitos subdomínios
    ext = tldextract.extract(url)
    subdominios = ext.subdomain.split(".")
    if len(subdominios) > 2:
        resultados.append(f"❌ Muitos subdomínios detectados: {ext.subdomain}")

    # 3. Caracteres especiais
    if re.search(r'[^a-zA-Z0-9\-._:/]', url):
        resultados.append("❌ Caracteres especiais incomuns na URL")

    # 4. Verificação com PhishTank (simulada)
    if verificar_phishtank(url):
        resultados.append("❌ URL presente na base do PhishTank")

    # 5. Idade do domínio (WHOIS)
    idade = idade_dominio(url)
    if idade is not None and idade < 90:
        resultados.append(f"❌ Domínio registrado há apenas {idade} dias")

    # 6. DNS dinâmico
    resultados += verificar_dns_dinamico(url)

    # 7. Certificado SSL
    resultados += verificar_ssl(url)

    # 8. Redirecionamentos suspeitos
    if verificar_redirecionamento(url):
        resultados.append("❌ Redirecionamento suspeito detectado")

    # 9. Similaridade com domínios legítimos
    dominio_url = f"{ext.domain}.{ext.suffix}"
    for legit in DOMINIOS_LEGITIMOS:
        similaridade = fuzz.ratio(dominio_url, legit)
        if similaridade >= 80 and dominio_url != legit:
            resultados.append(f"❌ Domínio semelhante a '{legit}' ({similaridade}%)")

    # 10. Formulário de login
    resultados += verificar_formularios_login(url)

    return resultados if resultados else ["✅ Nenhum sinal de phishing detectado"]

def verificar_phishtank(url):
    return "phish" in url.lower()

def idade_dominio(url):
    try:
        ext = tldextract.extract(url)
        dominio = f"{ext.domain}.{ext.suffix}"
        info = whois.whois(dominio)
        data = info.creation_date
        if isinstance(data, list):
            data = data[0]
        if data:
            return (datetime.now() - data).days
    except:
        return None

def verificar_dns_dinamico(url):
    resultados = []
    dominio = tldextract.extract(url).registered_domain
    for dinamico in DNS_DINAMICO:
        if dinamico in dominio:
            resultados.append(f"❌ Domínio usa DNS dinâmico ({dinamico})")
            break
    return resultados

def verificar_ssl(url):
    resultados = []
    try:
        hostname = urlparse(url).netloc.split(":")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        if expires < datetime.utcnow():
            resultados.append("❌ Certificado SSL expirado")

        issuer = dict(x[0] for x in cert['issuer'])

        emissor_nome = issuer.get("organizationName", "")
        if not any(confiavel in emissor_nome for confiavel in EMISSORES_CONFIAVEIS):
            resultados.append(f"⚠️ Certificado emitido por autoridade incomum: {emissor_nome}")

        subject = dict(x[0] for x in cert['subject'])
        common_name = subject.get('commonName', '')
        if not fnmatch(hostname, common_name.replace("*", "*")):
            resultados.append(f"❌ O certificado SSL não corresponde ao domínio ({common_name})")
    except Exception as e:
        resultados.append(f"❌ Erro ao verificar SSL: {str(e)}")
    return resultados

def verificar_redirecionamento(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return len(response.history) > 3
    except:
        return False

def verificar_formularios_login(url):
    resultados = []
    try:
        ext = tldextract.extract(url)
        dominio = f"{ext.domain}.{ext.suffix}"
        if dominio in DOMINIOS_LEGITIMOS:
            return []

        resposta = requests.get(url, timeout=5)
        soup = BeautifulSoup(resposta.text, "html.parser")
        formularios = soup.find_all("form")
        for form in formularios:
            inputs = form.find_all("input")
            for input_tag in inputs:
                if input_tag.get("type") == "password":
                    resultados.append("❌ Formulário de login detectado")
                    return resultados
        if formularios:
            resultados.append("⚠️ Formulários detectados, mas nenhum campo de senha")
    except Exception as e:
        resultados.append(f"❌ Erro ao analisar HTML: {str(e)}")
    return resultados
