"""
One-time setup: create the DynamoDB users table and seed the demo accounts.

Run ONCE (e.g. from AWS CloudShell) before switching USERS_BACKEND=dynamodb:

    pip3 install boto3 werkzeug
    AWS_REGION=us-east-1 USERS_TABLE_NAME=edustream-users-group3 \
        python3 scripts/init_users_table.py

Idempotent: re-running skips the table if it exists and skips existing users.
Requires dynamodb:CreateTable / DescribeTable / PutItem on the table.
"""

import os
import sys

import boto3
from botocore.exceptions import ClientError

# Allow importing users.py / config.py from the repo root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config  # noqa: E402
from users import DynamoDBUserStore, UserExistsError, _SEED_USERS, hash_password  # noqa: E402


def main() -> None:
    region = config.AWS_REGION
    table_name = config.USERS_TABLE_NAME
    ddb = boto3.client("dynamodb", region_name=region)

    try:
        ddb.create_table(
            TableName=table_name,
            AttributeDefinitions=[{"AttributeName": "username", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "username", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )
        print(f"Creating table '{table_name}' in {region} ...")
        ddb.get_waiter("table_exists").wait(TableName=table_name)
        print("Table is active.")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceInUseException":
            print(f"Table '{table_name}' already exists — reusing it.")
        else:
            raise

    store = DynamoDBUserStore(table_name, region)
    for username, password, role in _SEED_USERS:
        try:
            # Seeded accounts are authorized so the admin can manage the system
            # and the demo student can view content immediately.
            store.create(username, hash_password(password), role, authorized=True)
            print(f"Seeded user: {username} ({role}, authorized)")
        except UserExistsError:
            print(f"User '{username}' already exists — skipping.")

    print("Done. Set USERS_BACKEND=dynamodb on the instances to use this table.")


if __name__ == "__main__":
    main()
