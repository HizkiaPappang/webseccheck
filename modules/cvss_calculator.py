import math


CVSS_LABELS = {
    "AV": {"name": "Attack Vector", "values": {"N": ("Network", 0.85), "A": ("Adjacent", 0.62), "L": ("Local", 0.55), "P": ("Physical", 0.20)}},
    "AC": {"name": "Attack Complexity", "values": {"L": ("Low", 0.77), "H": ("High", 0.44)}},
    "PR": {"name": "Privileges Required", "values": {"N": ("None", {"U": 0.85, "C": 0.85}), "L": ("Low", {"U": 0.62, "C": 0.68}), "H": ("High", {"U": 0.27, "C": 0.50})}},
    "UI": {"name": "User Interaction", "values": {"N": ("None", 0.85), "R": ("Required", 0.62)}},
    "S": {"name": "Scope", "values": {"U": ("Unchanged", None), "C": ("Changed", None)}},
    "C": {"name": "Confidentiality", "values": {"N": ("None", 0.00), "L": ("Low", 0.22), "H": ("High", 0.56)}},
    "I": {"name": "Integrity", "values": {"N": ("None", 0.00), "L": ("Low", 0.22), "H": ("High", 0.56)}},
    "A": {"name": "Availability", "values": {"N": ("None", 0.00), "L": ("Low", 0.22), "H": ("High", 0.56)}},
}


def round_up_1_decimal(value):
    return math.ceil(value * 10) / 10


def calculate_cvss_31(metrics):
    av = CVSS_LABELS["AV"]["values"][metrics["AV"]][1]
    ac = CVSS_LABELS["AC"]["values"][metrics["AC"]][1]
    scope = metrics["S"]
    pr = CVSS_LABELS["PR"]["values"][metrics["PR"]][1][scope]
    ui = CVSS_LABELS["UI"]["values"][metrics["UI"]][1]
    c = CVSS_LABELS["C"]["values"][metrics["C"]][1]
    i = CVSS_LABELS["I"]["values"][metrics["I"]][1]
    a = CVSS_LABELS["A"]["values"][metrics["A"]][1]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow((iss - 0.02), 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope == "U":
        return min(round_up_1_decimal(impact + exploitability), 10.0)

    return min(round_up_1_decimal(1.08 * (impact + exploitability)), 10.0)


def cvss_vector(metrics):
    order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    return "CVSS:3.1/" + "/".join(f"{key}:{metrics[key]}" for key in order)


def cvss_numeric_value(code, value, scope):
    label, numeric = CVSS_LABELS[code]["values"][value]
    if code == "PR":
        numeric = numeric[scope]
    return label, numeric


def explain_cvss_31(metrics):
    scope = metrics["S"]

    av = CVSS_LABELS["AV"]["values"][metrics["AV"]][1]
    ac = CVSS_LABELS["AC"]["values"][metrics["AC"]][1]
    pr = CVSS_LABELS["PR"]["values"][metrics["PR"]][1][scope]
    ui = CVSS_LABELS["UI"]["values"][metrics["UI"]][1]
    c = CVSS_LABELS["C"]["values"][metrics["C"]][1]
    i = CVSS_LABELS["I"]["values"][metrics["I"]][1]
    a = CVSS_LABELS["A"]["values"][metrics["A"]][1]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow((iss - 0.02), 15)

    exploitability = 8.22 * av * ac * pr * ui
    base_score = calculate_cvss_31(metrics)

    matrix = []
    for code in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
        value = metrics[code]
        label, numeric = cvss_numeric_value(code, value, scope)
        matrix.append({
            "code": code,
            "name": CVSS_LABELS[code]["name"],
            "value": value,
            "label": label,
            "numeric": numeric,
        })

    return {
        "vector": cvss_vector(metrics),
        "matrix": matrix,
        "calculation": [
            f"ISS = 1 - [(1-C) × (1-I) × (1-A)] = {iss:.4f}",
            f"Impact = {'6.42 × ISS' if scope == 'U' else 'Changed scope impact formula'} = {impact:.4f}",
            f"Exploitability = 8.22 × AV × AC × PR × UI = {exploitability:.4f}",
            f"Base Score = {base_score:.1f}",
        ],
    }