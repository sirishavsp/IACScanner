from flask import Blueprint, request, jsonify, current_app, send_from_directory, render_template ,render_template_string, url_for
from models import Report, IssueCount
from extension import db
from collections import Counter
import os

report_blueprint = Blueprint('report_blueprint', __name__)

@report_blueprint.route('/generate_report/<path:filepath>', methods=['POST'])
def generate(filepath):
    data = request.get_json()
    results = data.get('results', [])
    report = generate_report(results, filepath)

    # Save the report in the "static/reports" directory
    report_folder = current_app.config['REPORT_FOLDER']
    if not os.path.exists(report_folder):
        os.makedirs(report_folder)

    report_filename = f'{filepath}_report.html'
    report_filepath = os.path.join(report_folder, report_filename)
    with open(report_filepath, 'w') as f:
        f.write(report)

    # Add the report to the database
    report_db_entry = Report.query.get(filepath)
    if report_db_entry is None:
        report_db_entry = Report(id=filepath, report_url=report_filename)
        db.session.add(report_db_entry)
    else:
        report_db_entry.report_url = report_filename
    db.session.commit()

    # Generate the URL for the report file
    report_url = url_for('static', filename=os.path.join('reports', report_filename), _external=True)

    return jsonify({'message': 'Report generated successfully', 'report_url': report_url})

@report_blueprint.route('/report/<path:filepath>', methods=['GET'])
def view_report(filepath):
    report_db_entry = Report.query.get(filepath)

    if report_db_entry is None or report_db_entry.report_url is None:
        return "Report not found", 404

    report_url = url_for('report_blueprint.view_report', filepath=filepath)
    pie_chart_url = url_for('report_blueprint.view_pie_chart', filepath=filepath)

    return render_template('view_report.html', report_url=report_url, pie_chart_url=pie_chart_url)


def generate_report(results, filepath):
    unique_results = process_results(results)  # Process the results to remove duplicates
    sorted_results = sort_results(unique_results)  # Sort the results

    # Count issue occurrences
    issue_counter = Counter(result['issue'] for result in sorted_results)

    for issue_name, count in issue_counter.items():
        issue_count = IssueCount.query.filter_by(issue_name=issue_name, report_id=filepath).first()
        if issue_count is None:
            issue_count = IssueCount(issue_name=issue_name, count=count, report_id=filepath)
        else:
            issue_count.count += count
        db.session.add(issue_count)
    db.session.commit()


    report = Report.query.get(filepath)
    report = Report.query.get(filepath)
    if report is not None:
        print(report.report_url)  # Debug statement

    with open('report2.html', 'r') as file:
        report_template = file.read()

    severity_counts = Counter(result['severity'] for result in sorted_results)
    chart_data = {
        'high': severity_counts.get('high', 0),
        'medium': severity_counts.get('medium', 0),
        'low': severity_counts.get('low', 0),
    }

    # Debug statements
    print(f"Results: {results}")
    print(f"Sorted Results: {sorted_results}")
    print(f"Issue Counts: {issue_counter}")
    print(f"Chart Data: {chart_data}")

    # Render the report using the template and the results
    report = render_template_string(report_template, results=sorted_results, chart_data=chart_data)

    return report

def process_results(results):
    flattened_results = flatten(results)
    unique_results = list(set(tuple(sorted(d.items())) for d in flattened_results))
    unique_results = [dict(t) for t in unique_results]
    return unique_results


@report_blueprint.route('/pie_chart/<path:filepath>', methods=['GET'])
def pie_chart(filepath):
    report_db_entry = Report.query.get(filepath)

    if report_db_entry is None or report_db_entry.issue_counts is None:
        return "Report not found", 404

    issue_counts = {issue.issue_name: issue.count for issue in report_db_entry.issue_counts}
    
    return render_template('view_pie_chart.html', issue_counts=issue_counts)






def sort_results(results):
    return sorted(results, key=lambda x: (x.get('severity', ''), x.get('line_number', '')))

def flatten(lst):
    flattened = []
    stack = [lst]

    while stack:
        curr = stack.pop()
        if isinstance(curr, list):
            stack.extend(curr)
        else:
            flattened.append(curr)

    return flattened
