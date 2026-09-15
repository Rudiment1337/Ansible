#!/usr/bin/env python3

import json
import os
import re
import sys

import requests
import urllib3


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


NETBOX_URL = os.environ.get(
    "NETBOX_API",
    "https://netbox.example.local",
).rstrip("/")

NETBOX_TOKEN = os.environ.get("NETBOX_TOKEN")


EXCLUDED_SERVICES = {
    "hmail",
    "rds",
    "nginx_k8s",
    "iis",
    "w_nginx",
    "w_apache",
    "rdp sign",
}


ALLOWED_CERTIFICATE_NAMES = {
    "*.example.local",
}


if not NETBOX_TOKEN:
    print(json.dumps({
        "_meta": {
            "hostvars": {},
        },
        "all": {
            "hosts": [],
            "children": [],
        },
    }))
    sys.exit(0)


SESSION = requests.Session()

SESSION.headers.update({
    "Authorization": f"Token {NETBOX_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json",
})

SESSION.verify = False


def empty_inventory():
    return {
        "_meta": {
            "hostvars": {},
        },
        "all": {
            "hosts": [],
            "children": [],
        },
    }


def fetch_all_pages(url):
    results = []

    while url:
        response = SESSION.get(
            url,
            timeout=30,
        )
        response.raise_for_status()

        data = response.json()

        results.extend(
            data.get("results", [])
        )

        url = data.get("next")

    return results


def get_all_services():
    url = (
        f"{NETBOX_URL}"
        "/api/ipam/services/"
        "?limit=1000"
    )

    services = fetch_all_pages(url)

    return {
        service["id"]: service
        for service in services
        if service.get("id") is not None
    }


def get_all_assignments():
    url = (
        f"{NETBOX_URL}"
        "/api/plugins/ssl/assignments/"
        "?limit=1000"
    )

    return fetch_all_pages(url)


def clean_device_name(name):
    if not name:
        return None

    return re.sub(
        r"\s*\([^)]*\)",
        "",
        name,
    ).strip()


def get_device_name(service):
    raw_name = None

    if service.get("device"):
        raw_name = service["device"].get("name")

    elif service.get("virtual_machine"):
        raw_name = service["virtual_machine"].get("name")

    elif service.get("parent"):
        raw_name = service["parent"].get("name")

    return clean_device_name(raw_name)


def get_first_ip(service):
    ipaddresses = service.get("ipaddresses") or []

    if not ipaddresses:
        return None

    address = ipaddresses[0].get("address")

    if not address:
        return None

    return address.split("/", 1)[0]


def get_custom_field(assignment, service, field_name):
    """
    Сначала проверяем custom_fields у CertificateAssignment.
    Если значение отсутствует, берем его у Service.
    """

    assignment_fields = (
        assignment.get("custom_fields")
        or {}
    )

    service_fields = (
        service.get("custom_fields")
        or {}
    )

    assignment_value = assignment_fields.get(field_name)

    if assignment_value is not None:
        return assignment_value

    return service_fields.get(field_name)


def make_host_name(
    device_name,
    service_name,
    service_id,
):
    clean_service_name = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        service_name or "service",
    ).strip("_")

    clean_device_name_value = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        device_name or "",
    ).strip("_")

    if clean_device_name_value:
        return (
            f"{clean_device_name_value}-"
            f"{clean_service_name}"
        )

    return (
        f"{clean_service_name}-"
        f"{service_id}"
    )


def add_to_group(
    groups,
    group_name,
    host_name,
):
    groups.setdefault(
        group_name,
        set(),
    ).add(host_name)


def build_inventory():
    assignments = get_all_assignments()
    services_map = get_all_services()

    inventory = empty_inventory()
    groups = {}

    for assignment in assignments:

        # Обрабатываем только назначения на Service.
        if assignment.get(
            "assigned_object_type"
        ) != "ipam.service":
            continue

        service_id = assignment.get(
            "assigned_object_id"
        )

        if not service_id:
            continue

        service = services_map.get(service_id)

        if not service:
            continue

        service_name = (
            service.get("name")
            or "service"
        )

        # Фильтрация сервисов без учета регистра.
        service_name_normalized = (
            service_name.strip().lower()
        )

        if (
            service_name_normalized
            in EXCLUDED_SERVICES
        ):
            continue

        certificate = (
            assignment.get("certificate")
            or {}
        )

        common_name = certificate.get(
            "common_name"
        )

        if not common_name:
            continue

        if common_name not in (
            ALLOWED_CERTIFICATE_NAMES
        ):
            continue

        ip = get_first_ip(service)
        device_name = get_device_name(service)

        host_name = make_host_name(
            device_name=device_name,
            service_name=service_name,
            service_id=service_id,
        )

        if device_name:
            ansible_host = device_name
        elif ip:
            ansible_host = ip
        else:
            ansible_host = host_name

        # Получаем формат сертификата.
        ssl_format_certs = get_custom_field(
            assignment,
            service,
            "ssl_format_certs",
        )

        certificate_format = ""

        if ssl_format_certs is not None:
            certificate_format = (
                str(ssl_format_certs)
                .strip()
                .lower()
            )

        # Формируем универсальные флаги.
        is_crt = certificate_format == "crt"
        is_pem = certificate_format == "pem"
        is_jks = certificate_format == "jks"
        is_pfx = certificate_format == "pfx"

        # Имя Docker-контейнера.
        ssl_docker_name = get_custom_field(
            assignment,
            service,
            "ssl_docker_name",
        )

        # URL сайта.
        site_url = get_custom_field(
            assignment,
            service,
            "url",
        )

        # Дата окончания сертификата.
        certificate_valid_to = certificate.get(
            "valid_to"
        )

        ssl_cert_expected_not_after = None

        if certificate_valid_to:
            ssl_cert_expected_not_after = (
                certificate_valid_to[:10]
            )

        vars_host = {
            "ansible_host": ansible_host,
            "ansible_ip": ip,
            "service_name": service_name,

            "certificate_common_name": common_name,
            "certificate_valid_to": certificate_valid_to,
            "ssl_cert_expected_not_after": (
                ssl_cert_expected_not_after
            ),

            "is_crt": is_crt,
            "is_pem": is_pem,
            "is_jks": is_jks,
            "is_pfx": is_pfx,

            "ssl_docker_name": ssl_docker_name,
            "site_url": site_url,
        }

        inventory["_meta"]["hostvars"][
            host_name
        ] = vars_host

        if host_name not in (
            inventory["all"]["hosts"]
        ):
            inventory["all"]["hosts"].append(
                host_name
            )

        # Группа по имени сервиса.
        service_group = re.sub(
            r"[^A-Za-z0-9_]+",
            "_",
            service_name,
        ).strip("_")

        if not service_group:
            service_group = "unknown"

        add_to_group(
            groups,
            f"service_{service_group}",
            host_name,
        )

        # Группа по имени сертификата.
        certificate_group = re.sub(
            r"[^A-Za-z0-9_]+",
            "_",
            common_name,
        ).strip("_")

        if not certificate_group:
            certificate_group = "unknown"

        add_to_group(
            groups,
            f"cert_{certificate_group}",
            host_name,
        )

    for group_name, hosts in groups.items():
        inventory[group_name] = {
            "hosts": sorted(hosts),
            "children": [],
        }

    return inventory


if __name__ == "__main__":
    try:
        print(
            json.dumps(
                build_inventory(),
                indent=2,
                ensure_ascii=False,
            )
        )

    except requests.RequestException as error:
        print(
            f"Ошибка запроса к NetBox API: {error}",
            file=sys.stderr,
        )

        print(
            json.dumps(
                empty_inventory()
            )
        )

        sys.exit(1)

    except Exception as error:
        print(
            f"Ошибка формирования inventory: {error}",
            file=sys.stderr,
        )

        print(
            json.dumps(
                empty_inventory()
            )
        )

        sys.exit(1)
