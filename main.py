import csv
import json
import os

from graph_client import fetch_live_users

USER_FILE = "data/sample_users.json"
REPORT_FILE = "user_audit_report.csv"
REPORT_MD_FILE = "user_audit_report.md"

USER_FIELDS = [
    "display_name",
    "user_principal_name",
    "account_enabled",
    "user_type",
    "licensed",
    "mfa_registered",
]


def load_users():
    client_id = os.environ.get("GRAPH_CLIENT_ID")
    tenant_id = os.environ.get("GRAPH_TENANT_ID")

    if client_id and tenant_id:
        try:
            print(f"\nFetching live users from Microsoft Graph (tenant {tenant_id})...")
            return fetch_live_users(client_id, tenant_id)
        except Exception as error:
            print(f"\nCould not fetch live users from Microsoft Graph: {error}")
            print("Falling back to local sample data.")

    try:
        with open(USER_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"\nUser file not found: {USER_FILE}")
        return []


def print_user(user):
    print("----------------------------------------")
    print(f"Name: {user['display_name']}")
    print(f"UPN: {user['user_principal_name']}")
    print(f"Account Enabled: {user['account_enabled']}")
    print(f"User Type: {user['user_type']}")
    print(f"Licensed: {user['licensed']}")
    print(f"MFA Registered: {user['mfa_registered']}")


def show_users(users):
    print("\n=== Entra ID Users ===")

    if not users:
        print("No users found.")
        return

    for index, user in enumerate(users, start=1):
        print(f"\nUser #{index}")
        print_user(user)


def filter_by_user_type(users):
    print("\n=== Filter by User Type ===")

    user_type = input("Enter user type to search (Member/Guest): ").lower()
    matches = []

    for user in users:
        if user_type in user["user_type"].lower():
            matches.append(user)

    show_users(matches)


def show_disabled_accounts(users):
    print("\n=== Disabled Accounts ===")

    matches = [user for user in users if not user["account_enabled"]]
    show_users(matches)


def show_users_without_mfa(users):
    print("\n=== Users Without MFA ===")

    matches = [user for user in users if not user["mfa_registered"]]
    show_users(matches)


def show_summary(users):
    print("\n=== User Audit Summary ===")

    if not users:
        print("No users found.")
        return

    total_users = len(users)
    member_users = 0
    guest_users = 0
    disabled_users = 0
    licensed_users = 0
    mfa_registered_users = 0

    for user in users:
        if user["user_type"].lower() == "member":
            member_users += 1
        elif user["user_type"].lower() == "guest":
            guest_users += 1

        if not user["account_enabled"]:
            disabled_users += 1

        if user["licensed"]:
            licensed_users += 1

        if user["mfa_registered"]:
            mfa_registered_users += 1

    print(f"Total Users: {total_users}")
    print(f"Member: {member_users}")
    print(f"Guest: {guest_users}")
    print(f"Disabled: {disabled_users}")
    print(f"Licensed: {licensed_users}")
    print(f"MFA Registered: {mfa_registered_users}")


def build_security_findings(users):
    findings = []

    for user in users:
        if not user["mfa_registered"]:
            severity = "High" if user["licensed"] else "Medium"
            findings.append({
                "user": user["user_principal_name"],
                "severity": severity,
                "finding": "No MFA method registered",
            })

        if not user["account_enabled"] and user["licensed"]:
            findings.append({
                "user": user["user_principal_name"],
                "severity": "Medium",
                "finding": "Disabled account still holds a license",
            })

        if user["user_type"].lower() == "guest" and not user["mfa_registered"]:
            findings.append({
                "user": user["user_principal_name"],
                "severity": "High",
                "finding": "Guest account without MFA",
            })

    return findings


def count_findings_by_severity(findings, severity):
    count = 0

    for finding in findings:
        if finding["severity"] == severity:
            count += 1

    return count


def show_security_findings(users):
    print("\n=== Security Findings Report ===")

    if not users:
        print("No users found.")
        return

    findings = build_security_findings(users)

    if not findings:
        print("No security findings found.")
        return

    for index, finding in enumerate(findings, start=1):
        print(f"\nFinding #{index}")
        print("----------------------------------------")
        print(f"User: {finding['user']}")
        print(f"Severity: {finding['severity']}")
        print(f"Finding: {finding['finding']}")

    print("\nFindings Summary")
    print(f"Total Findings: {len(findings)}")
    print(f"High: {count_findings_by_severity(findings, 'High')}")
    print(f"Medium: {count_findings_by_severity(findings, 'Medium')}")
    print(f"Low: {count_findings_by_severity(findings, 'Low')}")


def export_to_csv(users):
    print("\n=== Export User Audit Report ===")

    if not users:
        print("No users found.")
        return

    with open(REPORT_FILE, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=USER_FIELDS)
        writer.writeheader()
        writer.writerows(users)

    print(f"\nUser audit report exported successfully to {REPORT_FILE}")


def build_markdown_report(users):
    lines = ["# Microsoft Graph User Audit Report", ""]

    total_users = len(users)
    findings = build_security_findings(users)
    mfa_registered_users = sum(1 for user in users if user["mfa_registered"])

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total Users: {total_users}")
    lines.append(f"- MFA Registered: {mfa_registered_users}")
    lines.append(f"- Security Findings: {len(findings)}")
    lines.append(f"  - High: {count_findings_by_severity(findings, 'High')}")
    lines.append(f"  - Medium: {count_findings_by_severity(findings, 'Medium')}")
    lines.append(f"  - Low: {count_findings_by_severity(findings, 'Low')}")
    lines.append("")

    lines.append("## Users")
    lines.append("")
    lines.append("| Name | UPN | Enabled | Type | Licensed | MFA |")
    lines.append("|------|-----|---------|------|----------|-----|")

    for user in users:
        lines.append(
            f"| {user['display_name']} | {user['user_principal_name']} | "
            f"{user['account_enabled']} | {user['user_type']} | "
            f"{user['licensed']} | {user['mfa_registered']} |"
        )

    lines.append("")

    lines.append("## Security Findings")
    lines.append("")

    if not findings:
        lines.append("No security findings.")
    else:
        for finding in findings:
            lines.append(f"- **{finding['severity']}** – {finding['user']}: {finding['finding']}")

    lines.append("")

    return "\n".join(lines)


def export_to_markdown(users):
    print("\n=== Export User Audit Report (Markdown) ===")

    if not users:
        print("No users found.")
        return

    report = build_markdown_report(users)

    with open(REPORT_MD_FILE, "w") as file:
        file.write(report)

    print(f"\nUser audit report exported successfully to {REPORT_MD_FILE}")


def main():
    users = load_users()

    print("=" * 40)
    print("Microsoft Graph User Audit")
    print("=" * 40)

    while True:
        print("\n1. Show All Users")
        print("2. Filter by User Type")
        print("3. Show Disabled Accounts")
        print("4. Show Users Without MFA")
        print("5. Show Summary")
        print("6. Show Security Findings")
        print("7. Export to CSV")
        print("8. Export to Markdown")
        print("9. Exit")

        choice = input("\nChoose an option: ")

        if choice == "1":
            show_users(users)

        elif choice == "2":
            filter_by_user_type(users)

        elif choice == "3":
            show_disabled_accounts(users)

        elif choice == "4":
            show_users_without_mfa(users)

        elif choice == "5":
            show_summary(users)

        elif choice == "6":
            show_security_findings(users)

        elif choice == "7":
            export_to_csv(users)

        elif choice == "8":
            export_to_markdown(users)

        elif choice == "9":
            print("\nGoodbye!")
            break

        else:
            print("\nInvalid option. Please try again.")


if __name__ == "__main__":
    main()
