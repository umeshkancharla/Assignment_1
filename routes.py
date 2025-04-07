from flask import Blueprint, render_template, jsonify, request, redirect, url_for
from models import db, CVE, CPE
from services import nvd_service
from sqlalchemy import inspect, desc, asc
from datetime import datetime, timedelta

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    sort_by = request.args.get('sort_by', 'published_date')
    order = request.args.get('order', 'desc')
    
    # Base query
    query = CVE.query
    
    # Apply sorting
    if order == 'desc':
        query = query.order_by(desc(getattr(CVE, sort_by)))
    else:
        query = query.order_by(asc(getattr(CVE, sort_by)))
    
    # Paginate results
    pagination = query.paginate(page=page, per_page=10, error_out=False)
    cves = pagination.items
    
    # Get sync status
    sync_status = nvd_service.get_sync_status() if nvd_service.is_syncing else None
    
    return render_template('index.html',
                         cves=cves,
                         pagination=pagination,
                         sort_by=sort_by,
                         order=order,
                         sync_status=sync_status)

@bp.route('/cve/<string:cve_id>')
def cve_details(cve_id):
    cve = CVE.query.filter_by(cve_id=cve_id).first_or_404()
    cpes = CPE.query.filter_by(cve_id=cve_id).all()
    return render_template('cve_details.html', cve=cve, cpes=cpes)

@bp.route('/search')
def search():
    query = request.args.get('q', '')
    page = request.args.get('page', 1, type=int)
    
    if not query:
        return redirect(url_for('main.index'))
    
    # Search in CVE ID, description, and source identifier
    search_results = CVE.query.filter(
        (CVE.cve_id.ilike(f'%{query}%')) |
        (CVE.description.ilike(f'%{query}%')) |
        (CVE.source_identifier.ilike(f'%{query}%'))
    ).paginate(page=page, per_page=10, error_out=False)
    
    # Get sync status
    sync_status = nvd_service.get_sync_status() if nvd_service.is_syncing else None
    
    return render_template('search_results.html',
                         cves=search_results.items,
                         pagination=search_results,
                         query=query,
                         sync_status=sync_status)

@bp.route('/sync')
def sync_cves():
    try:
        # Check if database is initialized
        inspector = inspect(db.engine)
        if not inspector.has_table('cve'):
            return jsonify({'status': 'error', 'message': 'Database not initialized. Please run flask db upgrade first.'}), 500
        
        result = nvd_service.start_sync()
        return jsonify(result)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@bp.route('/sync/status')
def sync_status():
    """Get the current sync status."""
    if nvd_service.is_syncing:
        status = nvd_service.get_sync_status()
        return jsonify(status)
    else:
        return jsonify({'status': 'not_running'})

@bp.route('/sync/stop')
def stop_sync():
    """Stop the current sync process."""
    try:
        result = nvd_service.stop_sync()
        return jsonify(result)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500 