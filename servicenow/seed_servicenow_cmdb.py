import os
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# === CONFIG ===
load_dotenv()
INSTANCE = os.getenv("INSTANCE")
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")

BASE_URL = f"https://{INSTANCE}.service-now.com/api/now/table"

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}

auth = HTTPBasicAuth(USERNAME, PASSWORD)

# === DATA DEFINITIONS ===
services = ['Retail Services', 'Core Platform']
environments = ['dev', 'test', 'prod']
app_templates = [
    {"name": "Payment API", "short_description": "Handles payment processing"},
    {"name": "Auth Service", "short_description": "User authentication"},
    {"name": "Checkout Frontend", "short_description": "Customer-facing checkout UI"}
]

relationship_types = {
    "Runs on::Runs": None,
    "Contains::Contained by": None
}


# === HELPERS ===
def create_record(table, data):
    r = requests.post(f"{BASE_URL}/{table}", auth=auth, headers=HEADERS, json=data)
    r.raise_for_status()
    return r.json()["result"]["sys_id"]


def get_relationship_type_sys_id(name):
    r = requests.get(f"{BASE_URL}/cmdb_rel_type", auth=auth, headers=HEADERS,
                     params={"sysparm_query": f"name={name}"})
    r.raise_for_status()
    result = r.json().get("result")
    return result[0]["sys_id"] if result else None


def create_relationship(parent_id, child_id, rel_type_id):
    data = {
        "parent": parent_id,
        "child": child_id,
        "type": rel_type_id
    }
    return create_record("cmdb_rel_ci", data)


# === LOAD RELATIONSHIP TYPES ONCE ===
for rel_name in relationship_types:
    relationship_types[rel_name] = get_relationship_type_sys_id(rel_name)

# === MAIN SEEDING LOOP ===
for service in services:
    service_id = create_record("cmdb_ci_service", {
        "name": service,
        "short_description": f"{service} suite of digital services"
    })
    print(f"Created Service: {service}")

    for app in app_templates:
        app_name = f"{app['name']} [{service}]"
        app_id = create_record("cmdb_ci_appl", {
            "name": app_name,
            "short_description": app["short_description"]
        })
        print(f"  Created App: {app_name}")

        create_relationship(service_id, app_id, relationship_types["Runs on::Runs"])

        for env in environments:
            ci_name = f"ci-{app['name'].lower().replace(' ', '-')}-{env}"
            ci_id = create_record("cmdb_ci", {
                "name": ci_name,
                "short_description": f"{app['name']} deployed in {env}",
                "environment": env
            })
            print(f"    Created CI: {ci_name}")

            create_relationship(app_id, ci_id, relationship_types["Contains::Contained by"])

print("\n✅ CMDB Seeding Complete!")
