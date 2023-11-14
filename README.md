# OpenSearch Tools

A repository to store various tooling to manage Elasticsearch/OpenSearch clusters.

### Structure

```scripts``` dir, contains any scripts used to run against the clusters.

```utils``` dir, contains any utilities used to manage the clusters.

```Dockerfile``` contains the commands etc used to build an image, this can then be used to run the various scripts.

### Usage

To build the image locally, run the following command:

```docker build -t os-tools .```

To run the image locally, run the following command:

```docker run -it os-tools```

### Developing

It is recommended to have your IDE remote SSH interpreter setup to connect to an EC2 instance so you are inside your VPC. 

This way, you can make use of the native AWS CLI and not have to worry about credentials etc.

### Testing

To test against clusters, you will need to run the commands through your IDE's SSH interpreter.

### Scripts

#### scripts/es-snapshot.py 

The script is designed to register an Amazon S3 snapshot repository for an AWS ElasticSearch/OpenSearch cluster and then take a snapshot of all indices in the cluster. 

The script uses the boto3 library to interact with AWS services, the requests library to make HTTP requests, and the requests_aws4auth library to sign the requests. 

Here's a detailed explanation of the script:

We firstly and optionally send a message to a Slack channel using the `slack_start_message()` function.
Then, the script connects to the AWS Elasticsearch service using boto3 and retrieves the list of domain names. 
Then, it iterates through the domains, checks if the repo is already registered and if not, registers the snapshot repository for each domain using the `register_repo()` function.
Then, the script takes a snapshot of each domain using the `take_snapshot()` function, which sends a PUT request to the domain endpoint with the snapshot request payload.
Finally and optionally, the script sends the update to a Slack channel using the `slack_complete_message()` function.

This script is primarily aimed at older domains that do not have the Snapshot Lifecycle Management (SLM) feature available.

### TODO

Add various management scripts for routine checks, like index status, shard status, cluster health etc.. and document them here under a docs folder.

