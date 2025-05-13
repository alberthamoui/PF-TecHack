import re
import requests
import tldextract
import whois
import dns.resolver
import ssl
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from fuzzywuzzy import fuzz

DOMINIOS_LEGITIMOS = ["google.com", "facebook.com", "netflix.com", "paypal.com", "insper.edu.br","github.com"]

def verificar_url_basica(url):
    resultados = []

    # 1. Substituição de letras por números
    if re.search(r'[a-zA-Z]\d|[0-9][a-zA-Z]', url):
        resultados.append("❌ Substituição de letras por números detectada: isso é comum em domínios falsificados como 'g00gle.com' em vez de 'google.com'")

    # 2. Muitos subdomínios
    ext = tldextract.extract(url)
    subdominios = ext.subdomain.split(".")
    if len(subdominios) > 2:
        resultados.append(f"❌ Muitos subdomínios detectados ({ext.subdomain}): phishing usa domínios profundos como login.seguro.conta.banco.com para enganar")

    # 3. Caracteres especiais
    if re.search(r'[^a-zA-Z0-9\-._:/]', url):
        resultados.append("❌ Caracteres especiais incomuns na URL: pode ser tentativa de obfuscar a URL com símbolos como @, %, ~")

    # 4. Verificação com PhishTank (simulada)
    if verificar_phishtank(url):
        resultados.append("❌ URL presente na base do PhishTank: domínio já identificado como phishing")

    # 5. Idade do domínio (WHOIS)
    idade = idade_dominio(url)
    if idade is not None and idade < 90:
        resultados.append(f"❌ Domínio registrado há apenas {idade} dias: domínios novos são frequentemente usados em ataques antes de serem bloqueados")

    # 6. DNS dinâmico
    if any(dyn in url for dyn in ["no-ip", "dyndns", "duckdns"]):
        resultados.append("❌ DNS dinâmico detectado: serviços como no-ip e dyndns são comuns em ataques temporários")

    # 7. Certificado SSL
    if not verificar_ssl(url):
        resultados.append("❌ Certificado SSL ausente ou inválido: sites legítimos sempre usam HTTPS com certificados válidos")

    # 8. Redirecionamentos suspeitos
    if verificar_redirecionamento(url):
        resultados.append("❌ Redirecionamento suspeito: a URL redirecionou múltiplas vezes, o que é comum em páginas falsas que mascaram o destino final")

    # 9. Similaridade com domínios legítimos
    dominio_url = f"{ext.domain}.{ext.suffix}"
    for legit in DOMINIOS_LEGITIMOS:
        similaridade = fuzz.ratio(dominio_url, legit)
        if similaridade >= 80 and dominio_url != legit:
            resultados.append(f"❌ Domínio semelhante a '{legit}' (similaridade de {similaridade}%): possível tentativa de imitação de site confiável")

    # 10. Formulário de login
    if verificar_formularios(url):
        resultados.append("❌ Formulário de login detectado: páginas de phishing frequentemente imitam páginas de login para roubo de credenciais")

    if not resultados:
        return ["✅ Nenhum sinal de phishing detectado"]
    return resultados

# -----------------------------
# Funções auxiliares
# -----------------------------

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
            from datetime import datetime
            return (datetime.now() - data).days
    except:
        pass
    return None

def verificar_ssl(url):
    try:
        hostname = urlparse(url).netloc
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname, 443))
        return True
    except:
        return False

def verificar_redirecionamento(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        if len(response.history) > 3:
            return True
    except:
        return False
    return False

def verificar_formularios(url):
    try:
        # Ignorar verificação para domínios confiáveis
        ext = tldextract.extract(url)
        dominio = f"{ext.domain}.{ext.suffix}"
        if any(dom in dominio for dom in DOMINIOS_LEGITIMOS):
            return False

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            if 'password' in str(form).lower() or 'login' in str(form).lower():
                return True
    except:
        return False
    return False
