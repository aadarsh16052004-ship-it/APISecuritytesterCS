import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

class ReportGenerator:
    """Generates HTML report files."""

    def __init__(self, out_dir="reports"):
        self.out_dir = out_dir
        os.makedirs(self.out_dir, exist_ok=True)
        template_path = os.path.join(os.path.dirname(__file__), "..", "ui", "templates")
        self.env = Environment(loader=FileSystemLoader(template_path))

    def save_html(self, stats, vulns, recs):
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_path = os.path.join(self.out_dir, f"report_{ts}.html")
        html = self.env.get_template("results.html").render(
            stats=stats, vulns=vulns, recs=recs
        )
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html)
        return file_path
