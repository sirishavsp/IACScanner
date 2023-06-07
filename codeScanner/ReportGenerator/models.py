from .extension import db
from sqlalchemy import UniqueConstraint

class Report(db.Model):
    id = db.Column(db.String, primary_key=True)
    report_url = db.Column(db.String)
    issue_counts = db.relationship('IssueCount', backref='report')

class IssueCount(db.Model):
    __tablename__ = 'issue_count'
    id = db.Column(db.Integer, primary_key=True)
    issue_name = db.Column(db.String(255), nullable=False)
    count = db.Column(db.Integer, nullable=False)
    report_id = db.Column(db.String, db.ForeignKey('report.id'), nullable=False)
    __table_args__ = (UniqueConstraint('issue_name', 'report_id', name='_issue_report_uc'),)
