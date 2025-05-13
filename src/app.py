from flask import Flask, render_template, request
from analyzer import verificar_url_basica
import csv, os
from datetime import datetime
from flask import send_file

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    resultado = None
    if request.method == 'POST':
        url = request.form.get('url')
        resultado = verificar_url_basica(url)

        # Salvar resultado no log
        alertas = sum(1 for r in resultado if "❌" in r)
        status = "Suspeita" if alertas > 0 else "Segura"
        data = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open("logs.csv", "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if os.stat("logs.csv").st_size == 0:
                writer.writerow(["Data", "URL", "Status", "Qtd Alertas"])
            writer.writerow([data, url, status, alertas])

    return render_template('index.html', resultado=resultado)

@app.route('/historico')
def historico():
    registros = []
    alertas = []

    if os.path.exists("logs.csv"):
        with open("logs.csv", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)
            for linha in reader:
                registros.append(linha)
                if linha[2] == "Suspeita":
                    alertas.append(int(linha[3]))

    return render_template("historico.html", registros=reversed(registros), alertas=alertas)

@app.route('/exportar')
def exportar_csv():
    return send_file(os.path.join(os.path.dirname(__file__), "..", "logs.csv"), as_attachment=True)


if __name__ == '__main__':
    app.run(debug=True)
