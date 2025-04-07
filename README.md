# CVE Database Application

A Flask application that consumes and displays CVE (Common Vulnerabilities and Exposures) data from the NVD (National Vulnerability Database) API.

## Features

- Fetches CVE data from the NVD API
- Stores data in a SQLite database
- Provides a web interface to view and search CVEs
- Supports pagination and sorting
- Allows filtering by CVE ID, year, score, and last modified date
- Periodic data synchronization

## Setup

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Initialize the database:
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```

## Running the Application

1. Start the Flask development server:
   ```bash
   python app.py
   ```
2. Open your browser and navigate to `http://localhost:5000`

## API Documentation

### GET /cves/list
Displays the list of CVEs with pagination.

Query Parameters:
- `page`: Page number (default: 1)
- `per_page`: Number of items per page (default: 10)
- `sort_by`: Field to sort by (default: published_date)
- `sort_order`: Sort order (asc/desc, default: desc)

### GET /api/cves
Returns CVE data in JSON format.

Query Parameters:
- `cve_id`: Filter by CVE ID
- `year`: Filter by year
- `score`: Filter by minimum base score
- `last_modified_days`: Filter by last modified date (in days)

### GET /api/sync
Triggers a manual synchronization of CVE data from the NVD API.

## Testing

Run the test suite:
```bash
pytest
```

## Project Structure

```
.
├── app.py              # Main application file
├── config.py           # Configuration settings
├── models.py           # Database models
├── requirements.txt    # Project dependencies
├── services/
│   └── nvd_service.py  # NVD API service
├── static/
│   ├── css/
│   │   └── style.css   # CSS styles
│   └── js/
│       └── main.js     # JavaScript code
└── templates/
    └── index.html      # Main template
``` 