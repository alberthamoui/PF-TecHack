import csv
import matplotlib.pyplot as plt
from collections import Counter

def gerar_grafico_alertas():
    categorias = []

    with open("logs.csv", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # cabeçalho
        for linha in reader:
            if linha[2] == "Suspeita":
                categorias.append(int(linha[3]))

    if not categorias:
        print("Nenhum alerta para gerar gráfico.")
        return

    contagem = Counter(categorias)
    x = list(contagem.keys())
    y = list(contagem.values())

    plt.figure(figsize=(8, 5))
    plt.bar(x, y, color='crimson')
    plt.xlabel("Quantidade de alertas por URL")
    plt.ylabel("Frequência")
    plt.title("Distribuição de alertas em URLs analisadas")
    plt.tight_layout()
    plt.savefig("static/grafico_alertas.png")
    plt.close()
