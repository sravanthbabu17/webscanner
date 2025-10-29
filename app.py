from flask import Flask, render_template, request
from scanner import WebSecurityScanner

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url")
        depth = int(request.form.get("depth", 2))
        checks = request.form.getlist("checks")
        scanner = WebSecurityScanner(url, max_depth=depth, checks=checks)
        vulnerabilities, urls_scanned = scanner.scan()
        return render_template("results.html", url=url, vulnerabilities=vulnerabilities, urls_scanned=urls_scanned)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
