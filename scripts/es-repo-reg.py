import boto3
import requests
from requests_aws4auth import AWS4Auth

# Change host to your Elasticsearch domain's endpoint
host = '' # For example, my-test-domain.us-east-1.es.amazonaws.com
# Change region to your Elasticsearch domain's region
region = 'eu-central-1' # e.g. us-west-1
service = 'es'
credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)

# Register repository
path = '/_snapshot/es-backups' # the OpenSearch API endpoint
url = host + path

# Payload for creating a repository, refer to API: https://opensearch.org/docs/opensearch/rest-api/snapshot-restore/create-repository/
payload = {
  "type": "s3",
  "settings" : {
    "bucket" : "es-backups",
    "base_path" : "snapshots",
    "region" : "eu-central-1",
    "role_arn" : "arn:aws:iam::123456789012:role/MyRole"
  }
}

headers = {"Content-Type": "application/json"}

r = requests.put(url, auth=awsauth, json=payload, headers=headers)

print(r.status_code)
print(r.text)
