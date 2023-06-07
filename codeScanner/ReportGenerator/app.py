from flask import Flask, render_template
import os
from .extension import db
from .models import Report, IssueCount

def create_app():
    app = Flask(__name__)
    app.config['REPORT_FOLDER'] = os.path.join(app.root_path, 'static', 'reports')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iac20.db'
    db.init_app(app)
    with app.app_context():
        db.create_all()

    from report import report_blueprint
    app.register_blueprint(report_blueprint)

    return app

def check_report_status(report_path):
    if not os.path.exists(report_path) or os.stat(report_path).st_size == 0:
        return 'Pass'
    else:
        return 'Fail'

app = create_app()
app.config['DEBUG'] = True
from flask_migrate import Migrate

# Assume that `app` is your Flask application and `db` is your SQLAlchemy instance
migrate = Migrate(app, db)
@app.route('/consolidated_report')
def consolidated_report():
    issue_counts = {}
    reports = Report.query.all()

    for report in reports:
        for issue_count in report.issue_counts:
            issue_name = issue_count.issue_name
            count = issue_count.count
            if issue_name in issue_counts:
                issue_counts[issue_name] += count
            else:
                issue_counts[issue_name] = count

    return render_template('view_pie_chart.html', issue_counts=issue_counts)



@app.route('/')
def index():
    reports = []
    for report in os.listdir(app.config['REPORT_FOLDER']):
        full_path = os.path.join(app.config['REPORT_FOLDER'], report)
        status = check_report_status(full_path)
        reports.append((report, status))
        print(reports)  # Debug statement

    return render_template('index.html', reports=reports)

if __name__ == "__main__":
    app.run(port=5000, debug=True)
