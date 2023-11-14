
from botocore.config import Config
from datetime import datetime
from requests_aws4auth import AWS4Auth
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import boto3
import json
import logging
import os
import requests

## Variables
base_path = os.environ['BASE_PATH']
bucket = os.environ['S3_BUCKET_NAME']
env = os.environ['ENV'] # Useful if you have multiple environments, IE: dev, test, prod
log_level = os.environ['LOG_LEVEL']
region = os.environ['AWS_REGION']
repository_name = os.environ['REPO_NAME']
role_arn = os.environ['ROLE_ARN']
service = 'es'
skip_domains = os.environ['SKIP_DOMAINS'].split(',')
## End Variables

# Custom Boto config
boto_config = Config(
    region_name = region,
    signature_version = 'v4',
    retries = {
        'max_attempts': 10,
        'mode': 'standard'
    }
)

# Logging configuration
logging.basicConfig(level=log_level,
                    format='%(asctime)s - caller="%(name)s" function="%(funcName)s" level=%(levelname)s - %(message)s')

# Check STS Credentials - Only needed to really check if the role_arn is valid
sts = boto3.client('sts')
credentials = sts.get_caller_identity()

iam_credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(iam_credentials.access_key, iam_credentials.secret_key, region, service,
                   session_token=iam_credentials.token)
# logging.debug(credentials) - Same for this line, check if the role_arn is valid

# # Slack ENV Var configuration
if os.environ.get("SECRET_NAME") is None and os.environ.get("SLACK_CHANNEL") is None:
    logging.warning("SECRET_NAME and SLACK_CHANNEL are not defined.")
    secret_name = None
    slack_bot_token = None
    slack_channel = None
elif os.environ.get("SECRET_NAME") is None or os.environ.get("SLACK_CHANNEL") is None:
    logging.error("SECRET_NAME or SLACK_CHANNEL are not defined.")
    secret_name = None
    slack_bot_token = None
    slack_channel = None
else:
    # Get the slack secrets from AWS Secrets Manager
    secret_name = os.environ.get("SECRET_NAME")
    logging.info("SECRET_NAME and SLACK_CHANNEL are defined.")
    sm = boto3.client('secretsmanager', config=boto_config)
    response = sm.get_secret_value(
        SecretId=secret_name
    )
    secrets = json.loads(response['SecretString'])
    slack_bot_token = secrets['token']
    slack_channel = os.environ.get("SLACK_CHANNEL")
    slack_client = WebClient(token=slack_bot_token)

# Connect to OpenSearch service
es = boto3.client('es', config=boto_config)

# Get the list of OpenSearch domains
domains = es.list_domain_names()['DomainNames']


def get_date_time(custom_format):
    now = datetime.now()
    # date_time = now.strftime("%d-%m-%Y %H:%M:%S")
    return now.strftime(custom_format)


def start_log_message():
    custom_format = '%Y-%m-%d %H:%M:%S'
    logging.info(f"Starting OpenSearch snapshot process for {env.upper()} at: UTC {get_date_time(custom_format)}")
    if slack_bot_token is not None and slack_channel is not None:
        slack_client.chat_postMessage(channel="#"+slack_channel, text=f":arrow_forward: Starting OpenSearch snapshot process for *{env.upper()}* at: *UTC* {get_date_time(custom_format)}")


# Check if the snapshot repository exists
def check_repo_exists(domain):
    try:
        endpoint = get_domain_endpoint(domain)
        path = '_snapshot/' + repository_name
        url = f'https://{endpoint}/' + path
        r = requests.get(url, auth=awsauth)
        response = r.text
        if "repository_missing_exception" not in response:
            return True
    except:
        return False

# Get the ES Domain endpoint inside the VPC in URL format.
def get_domain_endpoint(domain):
    # Get the list of OpenSearch domains
    domain_status = es.describe_OpenSearch_domain(DomainName=domain['DomainName'])['DomainStatus']
    if 'Endpoints' in domain_status:
        endpoint = domain_status['Endpoints']['vpc']
        return endpoint


# Register the snapshot repository for each domain
def register_repo():
    for domain in domains:
        domain_name = domain["DomainName"]
        logging.info(f"Checking if snapshot repository exists for domain: {domain_name}")
        if slack_bot_token is not None and slack_channel is not None:
            slack_client.chat_postMessage(channel="#" + slack_channel,
                                          text=f":face_with_monocle: Checking if snapshot repository exists for domain: {domain_name}")
        if any(skip_domain in domain_name for skip_domain in skip_domains):
            logging.info(f"Found a domain to skip, skipping check.")
            if slack_bot_token is not None and slack_channel is not None:
                slack_client.chat_postMessage(channel="#" + slack_channel,
                                            text=f":x: Found a domain to skip, skipping check.")
        elif check_repo_exists(domain):
            logging.warning(f'Snapshot repository already exists for domain: {domain_name}." Skipping registration.')
        elif not check_repo_exists(domain):
            try:
                domain_name = domain["DomainName"]
                if slack_bot_token is not None and slack_channel is not None:
                    slack_client.chat_postMessage(channel="#" + slack_channel,
                                                  text=f":construction: Registering snapshot repository for endpoint: {domain_name}.")
                if any(skip_domain in domain_name for skip_domain in skip_domains):
                    logging.info(f"Found a domain to skip, skipping registration.")
                else:
                    logging.info(f'Snapshot repository does not exist for endpoint: {domain_name}')
                    logging.info(f'Registering snapshot repository for endpoint: {domain_name}')
                    endpoint = get_domain_endpoint(domain)
                    path = '_snapshot/' + repository_name
                    url = f'https://{endpoint}/' + path
                    headers = {"Content-Type": "application/json"}
                    base_dir = base_path + "/" + domain_name
                    payload = {
                        "type": "s3",
                        "settings": {
                            "bucket": bucket,
                            "base_path": base_dir,
                            "region": region,
                            "role_arn": role_arn
                        }
                    }

                    r = requests.put(url, auth=awsauth, json=payload, headers=headers)
                    logging.info(f'Repository registration status code: [{r.status_code}] and message: [{r.text}] for domain: {domain_name}')
                    if slack_bot_token is not None and slack_channel is not None:
                        repo_response = f":information_source: Snapshot repository registration response: [{r.text}] for domain: *{domain_name}*"
                        slack_client.chat_postMessage(channel="#" + slack_channel,
                                                      text=repo_response)
                        repo_status = f":white_check_mark: Snapshot repository registration status code: [{r.status_code}] for domain: *{domain_name}*"
                        slack_client.chat_postMessage(channel="#" + slack_channel,
                                                      text=repo_status)
            except Exception as e:
                logging.error(f'Repository registration error: {e}')
                if slack_bot_token is not None and slack_channel is not None:
                    slack_client.chat_postMessage(channel="#" + slack_channel,
                                                  text=f":x: Repository registration error: {e}")

# Take a snapshot for each domain
def take_snapshot():
    # Take a snapshot for each domain
    try:
        for domain in domains:
            domain_name = domain["DomainName"]
            endpoint = get_domain_endpoint(domain)
            if any(skip_domain in domain_name for skip_domain in skip_domains):
                logging.info(f"Found a domain to skip, skipping snapshot.")
                if slack_bot_token is not None and slack_channel is not None:
                    slack_client.chat_postMessage(channel="#" + slack_channel,
                                                text=f":x: Found a domain to skip, skipping snapshot.")
            else:
                logging.info(f'Taking snapshot for domain: {domain_name}')
                path = '_snapshot/' + repository_name + '/' + domain_name + '-snapshot' + '-' + get_date_time(custom_format='%Y-%m-%d_%H-%M-%S')
                url = f'https://{endpoint}/' + path
                headers = {"Content-Type": "application/json"}
                payload = {
                    "indices": "*",
                    "ignore_unavailable": "true",
                    "include_global_state": "true"
                }
                r = requests.put(url, auth=awsauth, json=payload, headers=headers)
                logging.info(f'Snapshot status code: [{r.status_code}] and message: [{r.text}] for domain: {domain_name}')
                if slack_bot_token is not None and slack_channel is not None:
                    snapshot_response = f":information_source: Snapshot response: [{r.text}] for domain: *{domain_name}*"
                    slack_client.chat_postMessage(channel="#" + slack_channel,
                                                  text=snapshot_response)
                    snapshot_status = f":white_check_mark: Snapshot status code: [{r.status_code}] for domain: *{domain_name}*"
                    slack_client.chat_postMessage(channel="#" + slack_channel,
                                                  text=snapshot_status)
    except Exception as e:
        logging.error(f'Snapshot error: {e}')
        if slack_bot_token is not None and slack_channel is not None:
            slack_client.chat_postMessage(channel="#" + slack_channel,
                                          text=f":x: Snapshot failed with status error: {e}")


def end_log_message():
    custom_format = '%Y-%m-%d %H:%M:%S'
    logging.info(f"OpenSearch snapshot process for {env.upper()}, Completed at: UTC {get_date_time(custom_format)}")
    if slack_bot_token is not None and slack_channel is not None:
        slack_client.chat_postMessage(channel="#"+slack_channel, text=f":tada: OpenSearch snapshot process for *{env.upper()}*, Completed at: *UTC* {get_date_time(custom_format)}")

if __name__ == '__main__':
    start_log_message()
    register_repo()
    take_snapshot()
    end_log_message()
