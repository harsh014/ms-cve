from datetime import datetime, date, timedelta
import pandas as pd
import requests

VULNERABILITY_HEADER = [
    "release_date",
    "product_family",
    "product_id",
    "product_name",
    "impact",
    "severity",
    "kb_article",
    "cve_code",
]


class Remediation:
    def __init__(self, data):
        self.kb = "KB" + data.get("Description").get("Value")
        # self.url = data.get('URL')
        self.product = data.get("ProductID")


class Threats:
    def __init__(self, data):
        self.description = data.get("Description").get("Value")
        self.product = data.get("ProductID")[0]
        self.type = data.get("Type")  # {type=0:impact} {type=3:severity}


class Vulnerability:
    def __init__(self, data):
        # self.title = data.get('Title').get('Value')
        # self.notes = data.get('Notes')
        # self.discovery_date_specified = data.get('DiscoveryDateSpecified')
        # self.release_date_specified = data.get('ReleaseDateSpecified')
        self.cve = data.get("CVE")
        self.product = data.get("ProductStatuses")[0].get("ProductID")
        self.threats = [
            Threats(item) for item in data.get("Threats") if item.get("Type") != 1
        ]
        # self.cvss_score_sets = data.get('CVSSScoreSets')
        self.remediations = [
            Remediation(item)
            for item in data.get("Remediations")
            if item.get("Type") == 2
               and str(item.get("Description").get("Value"))[0].isdigit()
        ]
        # self.acknowledgments = data.get('Acknowledgments')
        # self.ordinal = data.get('Ordinal')
        self.revision_history = str(
            datetime.strptime(
                data.get("RevisionHistory")[0].get("Date"), "%Y-%m-%dT%H:%M:%S"
            ).date()
        )


class Product:
    def __init__(self, data, name):
        self.product = data.get("ProductID")
        self.product_name = data.get("Value")
        self.product_family = name


class CVRF:
    def __init__(self, data):
        # self.document_title = data.get('DocumentTitle').get('Value')
        # self.document_type = data.get('DocumentType').get('Value')
        # self.document_publisher = data.get('DocumentPublisher')
        # self.document_tracking = data.get('DocumentTracking')
        # self.document_notes = data.get('DocumentNotes')
        self.product_mapping = [
            Product(each, item.get("Name"))
            for item in data.get("ProductTree").get("Branch")[0].get("Items")
            for each in item.get("Items")
        ]
        self.vulnerabilities = [
            Vulnerability(item) for item in data.get("Vulnerability")
        ]


def single_vulnerability(vulnerability):
    impact_product_list = []
    severity_product_list = []
    kb_product_list = []

    cve_product_date_dict = {
        "cve_code": vulnerability.cve,
        "product_id": vulnerability.product,
        "release_date": vulnerability.revision_history,
    }

    for threat in vulnerability.threats:
        if threat.type == 0:
            impact_product_dict = {
                "product_id": threat.product,
                "impact": threat.description,
            }
            impact_product_list.append(impact_product_dict)
        else:
            severity_product_dict = {
                "product_id": threat.product,
                "severity": threat.description,
            }
            severity_product_list.append(severity_product_dict)

    for remediation in vulnerability.remediations:
        kb_product_dict = {
            "kb_article": remediation.kb,
            "product_id": remediation.product,
        }
        kb_product_list.append(kb_product_dict)

    cve_product_date_df = pd.DataFrame(cve_product_date_dict).explode("product_id")

    if len(kb_product_list) != 0:
        kb_product_df = pd.DataFrame(kb_product_list).explode("product_id")
    else:
        kb_product_df = pd.DataFrame(columns=["kb_article", "product_id"])

    impact_product_df = pd.DataFrame(impact_product_list)
    severity_product_df = pd.DataFrame(severity_product_list)
    impact_severity_product_df = impact_product_df.merge(
        severity_product_df, on="product_id"
    )

    if not kb_product_df.empty:
        first_master_data = cve_product_date_df.merge(kb_product_df, on="product_id")
        second_master_data = first_master_data.merge(
            impact_severity_product_df, on="product_id"
        )
        return second_master_data


def create_product_df(product_mapping):
    product_mapping_dict = []
    for item in product_mapping:
        single_product_mapping_dict = {
            "product_id": item.product,
            "product_name": item.product_name,
            "product_family": item.product_family,
        }
        product_mapping_dict.append(single_product_mapping_dict)
    return pd.DataFrame(product_mapping_dict)


def map_vulnerabilities(api_response_json):
    vulnerability_list = []

    for vulnerability in api_response_json.vulnerabilities:
        vulnerability_list.append(single_vulnerability(vulnerability))

    try:
        kb_cve_df = pd.concat(vulnerability_list, ignore_index=True)
        product_df = create_product_df(api_response_json.product_mapping)
        master_data = kb_cve_df.merge(product_df, on="product_id")
    except ValueError:
      print("MSRC API sent the CVE data, but no remediations have been found for the same. Therefore, the parsed data is null.")
    return master_data


def get_url(requested_date=date.today()):
    base_url = "https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/"
    return (
        base_url
        + str(requested_date.year)
        + "-"
        + str(requested_date.strftime("%b")).upper()
    )


def get_msrc_data(accept="csv"):
    headers = {"Accept": "application/json"}
    print(f"Contacting MSRC at {get_url()}")
    api_response = requests.get(get_url(), headers=headers)

    if api_response.status_code == 404:
      print("MSRC API sent a 404 response. The requested data is not yet populated by Microsoft.")

    if api_response.status_code != 200:
      print("An HttpException was raised. MSRC is unreachable.")

    api_response_json = CVRF(api_response.json())
    cve_to_kb = map_vulnerabilities(api_response_json)[VULNERABILITY_HEADER]
    cve_to_kb_df = pd.DataFrame.from_dict(cve_to_kb)

    if accept == "csv":
        return cve_to_kb_df.to_csv(index=False)
    else:  # json
        return cve_to_kb_df.to_dict(orient="records")

if __name__ == "__main__":
  print(get_msrc_data()
