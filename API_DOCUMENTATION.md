# NVD CVE API Documentation

## Overview
This API provides access to CVE (Common Vulnerabilities and Exposures) data from the National Vulnerability Database (NVD). It supports operations for listing, filtering, and viewing detailed CVE information.

## Base URL
```
http://localhost:5000
```

## Authentication
No authentication is required for these endpoints.

## Endpoints

### 1. List CVEs
Retrieves a paginated list of CVEs with optional filtering and sorting.

```
GET /api/cves
```

#### Query Parameters
| Parameter | Type | Required | Description | Default |
|-----------|------|----------|-------------|---------|
| page | integer | No | Page number | 1 |
| per_page | integer | No | Results per page (10, 50, or 100) | 10 |
| sort_by | string | No | Field to sort by (cve_id, published_date, base_score) | published_date |
| order | string | No | Sort order (asc, desc) | desc |
| year | integer | No | Filter by year | None |
| min_score | float | No | Minimum CVSS score | None |
| max_score | float | No | Maximum CVSS score | None |
| last_modified_days | integer | No | Filter by last modified within N days | None |
| search | string | No | Search term for CVE ID or description | None |

#### Response
```json
{
    "cves": [
        {
            "cve_id": "CVE-2023-1234",
            "description": "Vulnerability description...",
            "published_date": "2023-01-01T00:00:00Z",
            "last_modified": "2023-01-02T00:00:00Z",
            "base_score": 7.5,
            "vuln_status": "Analyzed"
        }
    ],
    "pagination": {
        "page": 1,
        "per_page": 10,
        "total": 1000,
        "pages": 100
    }
}
```

### 2. Get CVE Details
Retrieves detailed information about a specific CVE.

```
GET /api/cves/<cve_id>
```

#### Path Parameters
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| cve_id | string | Yes | CVE identifier (e.g., CVE-2023-1234) |

#### Response
```json
{
    "cve_id": "CVE-2023-1234",
    "source_identifier": "cve@mitre.org",
    "published_date": "2023-01-01T00:00:00Z",
    "last_modified": "2023-01-02T00:00:00Z",
    "vuln_status": "Analyzed",
    "description": "Detailed vulnerability description...",
    "cvss_metrics": {
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "base_score": 9.8,
        "base_severity": "CRITICAL",
        "exploitability_score": 3.9,
        "impact_score": 5.9
    },
    "cpe_list": [
        {
            "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
            "match_criteria_id": "12345",
            "vulnerable": true
        }
    ]
}
```

### 3. Start CVE Sync
Initiates the background synchronization process to update CVE data.

```
POST /sync
```

#### Response
```json
{
    "status": "started",
    "message": "Sync process started"
}
```

### 4. Get Sync Status
Retrieves the current status of the CVE synchronization process.

```
GET /sync/status
```

#### Response
```json
{
    "status": "running",
    "processed_count": 500,
    "total_count": 1000,
    "current_page": 5,
    "error": null
}
```

### 5. Stop CVE Sync
Stops the ongoing CVE synchronization process.

```
POST /sync/stop
```

#### Response
```json
{
    "status": "success",
    "message": "Sync process stopped"
}
```

## Error Responses

All endpoints may return the following error responses:

### 400 Bad Request
```json
{
    "error": "Invalid request parameters",
    "details": "Specific error message"
}
```

### 404 Not Found
```json
{
    "error": "Resource not found",
    "details": "CVE not found"
}
```

### 500 Internal Server Error
```json
{
    "error": "Internal server error",
    "details": "Error message"
}
```

## Rate Limiting
- No rate limiting is currently implemented
- Please be mindful of API usage to avoid overwhelming the server

## Data Format
- All dates are returned in ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)
- CVSS scores are returned as floating-point numbers
- Boolean values are returned as true/false

## Examples

### Example 1: List CVEs with Filtering
```
GET /api/cves?year=2023&min_score=7.0&sort_by=base_score&order=desc
```

### Example 2: Search CVEs
```
GET /api/cves?search=apache&per_page=50
```

### Example 3: Get CVE Details
```
GET /api/cves/CVE-2023-1234
```

## Notes
- The API is designed to be RESTful and follows standard HTTP conventions
- All responses are in JSON format
- The API supports CORS for cross-origin requests
- Pagination is implemented using page numbers and results per page
- Sorting is available on multiple fields
- Filtering can be combined with sorting and pagination 