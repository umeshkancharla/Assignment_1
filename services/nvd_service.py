import requests
from datetime import datetime
from models import db, CVE, CPE
from config import Config
from flask import current_app
import threading
import queue
import time

class NVDService:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(NVDService, cls).__new__(cls)
            # Initialize instance attributes
            cls._instance.base_url = Config.NVD_API_BASE_URL
            cls._instance.results_per_page = Config.RESULTS_PER_PAGE
            cls._instance._sync_status = {}
            cls._instance._sync_lock = threading.Lock()
            cls._instance._sync_thread = None
            cls._instance._app = None
            cls._instance._stop_sync = False
        return cls._instance
    
    def init_app(self, app):
        """Initialize the service with a Flask application instance."""
        self._app = app
    
    @property
    def is_syncing(self):
        with self._sync_lock:
            return bool(self._sync_thread and self._sync_thread.is_alive())
    
    def get_sync_status(self):
        with self._sync_lock:
            return dict(self._sync_status)
    
    def stop_sync(self):
        """Stop the sync process gracefully."""
        if not self.is_syncing:
            return {'status': 'not_running', 'message': 'No sync process is running'}
        
        with self._sync_lock:
            self._stop_sync = True
            self._sync_status['status'] = 'stopping'
        
        # Wait for the thread to finish
        if self._sync_thread:
            self._sync_thread.join(timeout=5)  # Wait up to 5 seconds
        
        with self._sync_lock:
            if self._sync_thread and self._sync_thread.is_alive():
                return {'status': 'error', 'message': 'Failed to stop sync process'}
            self._sync_status['status'] = 'stopped'
            return {'status': 'success', 'message': 'Sync process stopped'}
    
    def fetch_cves(self, start_index=0):
        params = {
            'startIndex': start_index,
            'resultsPerPage': self.results_per_page
        }
        
        try:
            self._app.logger.info(f"Fetching CVEs from NVD API with startIndex={start_index}")
            response = requests.get(self.base_url, params=params)
            response.raise_for_status()
            data = response.json()
            
            if 'vulnerabilities' not in data:
                raise Exception("Invalid API response format: missing 'vulnerabilities' key")
                
            return data
        except requests.exceptions.RequestException as e:
            self._app.logger.error(f"Error fetching CVEs: {str(e)}")
            raise Exception(f"Failed to fetch CVEs from NVD API: {str(e)}")
    
    def process_cve(self, cve_data):
        try:
            cve = cve_data['cve']
            
            # Get description in English
            description = next(
                (desc['value'] for desc in cve['descriptions'] if desc['lang'] == 'en'),
                None
            )
            
            # Get CVSS metrics
            metrics = cve.get('metrics', {})
            cvss_data = None
            
            # Try to get CVSS v2 metrics first
            if 'cvssMetricV2' in metrics:
                cvss_metric = metrics['cvssMetricV2'][0]
                cvss_data = cvss_metric['cvssData']
                exploitability_score = cvss_metric.get('exploitabilityScore')
                impact_score = cvss_metric.get('impactScore')
                base_severity = cvss_metric.get('baseSeverity')
            # Fallback to v3.x if v2 not available
            elif 'cvssMetricV31' in metrics:
                cvss_metric = metrics['cvssMetricV31'][0]
                cvss_data = cvss_metric['cvssData']
                exploitability_score = cvss_metric.get('exploitabilityScore')
                impact_score = cvss_metric.get('impactScore')
                base_severity = cvss_data.get('baseSeverity')
            elif 'cvssMetricV30' in metrics:
                cvss_metric = metrics['cvssMetricV30'][0]
                cvss_data = cvss_metric['cvssData']
                exploitability_score = cvss_metric.get('exploitabilityScore')
                impact_score = cvss_metric.get('impactScore')
                base_severity = cvss_data.get('baseSeverity')
            else:
                cvss_data = {}
                exploitability_score = None
                impact_score = None
                base_severity = None
            
            # Create CVE data dictionary
            cve_dict = {
                'cve_id': cve['id'],
                'source_identifier': cve.get('sourceIdentifier'),
                'published_date': datetime.fromisoformat(cve['published'].replace('Z', '+00:00')),
                'last_modified': datetime.fromisoformat(cve['lastModified'].replace('Z', '+00:00')),
                'vuln_status': cve.get('vulnStatus'),
                'description': description,
                'vector_string': cvss_data.get('vectorString'),
                'base_score': cvss_data.get('baseScore'),
                'access_vector': cvss_data.get('accessVector'),
                'access_complexity': cvss_data.get('accessComplexity'),
                'authentication': cvss_data.get('authentication'),
                'confidentiality_impact': cvss_data.get('confidentialityImpact'),
                'integrity_impact': cvss_data.get('integrityImpact'),
                'availability_impact': cvss_data.get('availabilityImpact'),
                'base_severity': base_severity,
                'exploitability_score': exploitability_score,
                'impact_score': impact_score
            }
            
            # Process CPE data
            cpe_list = []
            for config in cve.get('configurations', []):
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe_list.append({
                            'criteria': cpe_match['criteria'],
                            'match_criteria_id': cpe_match['matchCriteriaId'],
                            'vulnerable': cpe_match['vulnerable']
                        })
            
            return cve_dict, cpe_list
            
        except Exception as e:
            self._app.logger.error(f"Error processing CVE data: {str(e)}")
            raise Exception(f"Failed to process CVE data: {str(e)}")
    
    def _sync_worker(self):
        """Background worker for syncing CVEs."""
        # Push the application context
        with self._app.app_context():
            try:
                with self._sync_lock:
                    self._sync_status = {
                        'status': 'running',
                        'processed_count': 0,
                        'total_count': None,
                        'current_page': 0,
                        'error': None
                    }
                    self._stop_sync = False
                
                start_index = 0
                total_results = None
                processed_count = 0
                
                while (total_results is None or start_index < total_results) and not self._stop_sync:
                    data = self.fetch_cves(start_index)
                    if not data:
                        break
                    
                    total_results = data['totalResults']
                    vulnerabilities = data['vulnerabilities']
                    
                    with self._sync_lock:
                        self._sync_status['total_count'] = total_results
                    
                    for vuln in vulnerabilities:
                        # Check if stop was requested
                        if self._stop_sync:
                            break
                            
                        try:
                            cve_dict, cpe_list = self.process_cve(vuln)
                            
                            # Check if CVE already exists
                            existing_cve = CVE.query.filter_by(cve_id=cve_dict['cve_id']).first()
                            
                            if existing_cve:
                                # Update existing CVE
                                for key, value in cve_dict.items():
                                    setattr(existing_cve, key, value)
                                # Delete existing CPEs
                                CPE.query.filter_by(cve_id=existing_cve.cve_id).delete()
                            else:
                                # Create new CVE
                                existing_cve = CVE(**cve_dict)
                                db.session.add(existing_cve)
                                db.session.flush()  # To get the CVE ID
                            
                            # Add new CPEs
                            for cpe_data in cpe_list:
                                cpe = CPE(cve_id=existing_cve.cve_id, **cpe_data)
                                db.session.add(cpe)
                            
                            db.session.commit()
                            
                            processed_count += 1
                            with self._sync_lock:
                                self._sync_status['processed_count'] = processed_count
                                
                        except Exception as e:
                            self._app.logger.error(f"Error processing CVE {vuln.get('cve', {}).get('id', 'unknown')}: {str(e)}")
                            continue
                    
                    start_index += self.results_per_page
                    with self._sync_lock:
                        self._sync_status['current_page'] = start_index // self.results_per_page
                    
                    self._app.logger.info(f"Processed {processed_count} CVEs so far")
                
                with self._sync_lock:
                    if self._stop_sync:
                        self._sync_status['status'] = 'stopped'
                        self._app.logger.info(f"Sync stopped. Processed {processed_count} CVEs")
                    else:
                        self._sync_status['status'] = 'completed'
                        self._app.logger.info(f"Completed CVE sync. Total processed: {processed_count}")
                
            except Exception as e:
                error_msg = f"Error during CVE sync: {str(e)}"
                self._app.logger.error(error_msg)
                with self._sync_lock:
                    self._sync_status['status'] = 'error'
                    self._sync_status['error'] = error_msg
    
    def start_sync(self):
        """Start the sync process in a background thread if not already running."""
        if not self._app:
            raise RuntimeError("Service not initialized with Flask app. Call init_app() first.")
            
        if self.is_syncing:
            return {'status': 'already_running', 'message': 'Sync is already in progress'}
        
        self._sync_thread = threading.Thread(target=self._sync_worker)
        self._sync_thread.daemon = True  # Thread will be terminated when main thread exits
        self._sync_thread.start()
        
        return {'status': 'started', 'message': 'Sync process started'}