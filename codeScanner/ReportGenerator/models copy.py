
from extension import db

class Report(db.Model):
    id = db.Column(db.String, primary_key=True)
    issue_counts = db.Column(db.PickleType)
    report_url = db.Column(db.String)


class IssueCount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    issue_name = db.Column(db.String(255), unique=True, nullable=False)
    count = db.Column(db.Integer, nullable=False, default=0)
    report_id = db.Column(db.String, db.ForeignKey('report.id'), nullable=False)

    