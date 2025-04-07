from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class CPE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), db.ForeignKey('cve.cve_id'))
    criteria = db.Column(db.String(255), nullable=False)
    match_criteria_id = db.Column(db.String(50), nullable=False)
    vulnerable = db.Column(db.Boolean, default=True)

class CVE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20), unique=True, nullable=False)
    source_identifier = db.Column(db.String(100))
    published_date = db.Column(db.DateTime, nullable=False)
    last_modified = db.Column(db.DateTime, nullable=False)
    vuln_status = db.Column(db.String(20))
    description = db.Column(db.Text)
    
    # CVSS v2 Metrics
    vector_string = db.Column(db.String(100))
    base_score = db.Column(db.Float)
    access_vector = db.Column(db.String(20))
    access_complexity = db.Column(db.String(20))
    authentication = db.Column(db.String(20))
    confidentiality_impact = db.Column(db.String(20))
    integrity_impact = db.Column(db.String(20))
    availability_impact = db.Column(db.String(20))
    base_severity = db.Column(db.String(20))
    exploitability_score = db.Column(db.Float)
    impact_score = db.Column(db.Float)
    
    # Relationships
    cpes = db.relationship('CPE', backref='cve', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'source_identifier': self.source_identifier,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified': self.last_modified.isoformat() if self.last_modified else None,
            'vuln_status': self.vuln_status,
            'description': self.description,
            'vector_string': self.vector_string,
            'base_score': self.base_score,
            'access_vector': self.access_vector,
            'access_complexity': self.access_complexity,
            'authentication': self.authentication,
            'confidentiality_impact': self.confidentiality_impact,
            'integrity_impact': self.integrity_impact,
            'availability_impact': self.availability_impact,
            'base_severity': self.base_severity,
            'exploitability_score': self.exploitability_score,
            'impact_score': self.impact_score,
            'cpes': [{
                'criteria': cpe.criteria,
                'match_criteria_id': cpe.match_criteria_id,
                'vulnerable': cpe.vulnerable
            } for cpe in self.cpes]
        } 