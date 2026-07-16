#!/usr/bin/env python3
"""
Generate human-readable reports from BOD 26-04 analysis.
Creates: CSV, text summary, and enhanced JSON.
"""
import json
import csv
import sys
from datetime import datetime
from pathlib import Path


def generate_text_report(report_data, output_file):
    """Generate human-readable text report."""
    with open(output_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write("BOD 26-04 RISK TIERING REPORT\n")
        f.write("="*80 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Coverage Summary
        cov = report_data['coverage']
        f.write("COVERAGE SUMMARY\n")
        f.write("-"*80 + "\n")
        f.write(f"Total Findings: {cov['total_findings']}\n")
        f.write(f"Determined: {cov['determined']} ({cov['coverage_pct']}%)\n")
        f.write(f"Undetermined: {cov['undetermined']}\n")
        f.write(f"KEV Findings: {cov['kev_findings_total']}\n")
        f.write(f"KEV Coverage: {cov['kev_coverage_pct']}%\n\n")

        # Tier Distribution
        dist = report_data['tier_distribution']
        f.write("TIER DISTRIBUTION\n")
        f.write("-"*80 + "\n")
        f.write(f"3-Day + Forensic: {dist['3_days_forensic']}\n")
        f.write(f"3-Day: {dist['3_days']}\n")
        f.write(f"14-Day: {dist['14_days']}\n")
        f.write(f"60-Day: {dist['60_days']}\n")
        f.write(f"Fix on Upgrade: {dist['fix_on_upgrade']}\n")
        f.write(f"Undetermined: {dist['undetermined']}\n\n")

        # 3-Day Action Queue
        queue = report_data['three_day_action_queue']
        f.write("="*80 + "\n")
        f.write(f"3-DAY ACTION QUEUE ({len(queue)} items)\n")
        f.write("="*80 + "\n\n")

        if not queue:
            f.write("No findings in 3-day queue.\n\n")
        else:
            for i, finding in enumerate(queue, 1):
                f.write(f"{i}. {finding['asset_name']}\n")
                f.write(f"   Asset ID: {finding['asset_id']}\n")
                f.write(f"   CVE: {finding['cve_id']}\n")
                f.write(f"   Plugin: {finding['plugin_name']}\n")
                tier = finding['tier']
                f.write(f"   KEV Date: {tier['trigger_date']}\n")
                f.write(f"   Deadline: {tier['deadline']}\n")
                if tier['days_remaining'] < 0:
                    f.write(f"   Status: OVERDUE by {abs(tier['days_remaining'])} days\n")
                else:
                    f.write(f"   Days Remaining: {tier['days_remaining']}\n")
                f.write(f"   Forensic Triage: {'YES' if tier['forensic_triage_required'] else 'NO'}\n")
                f.write("\n")

        # Forensic Triage Required
        forensic = report_data['forensic_triage_required']
        if forensic:
            f.write("="*80 + "\n")
            f.write(f"FORENSIC TRIAGE REQUIRED ({len(forensic)} assets)\n")
            f.write("="*80 + "\n\n")

            for i, finding in enumerate(forensic, 1):
                f.write(f"{i}. {finding['asset_name']} - {finding['cve_id']}\n")
                f.write(f"   {finding['plugin_name']}\n\n")


def generate_csv_summary(report_data, output_file):
    """Generate CSV summary of all findings."""
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)

        # Header
        writer.writerow([
            'Asset Name',
            'Asset ID',
            'CVE ID',
            'Plugin ID',
            'Plugin Name',
            'In KEV',
            'Tier',
            'Timeline Days',
            'Forensic Required',
            'Trigger Date',
            'Deadline',
            'Days Remaining',
            'Table Row',
            'Status'
        ])

        # Get all findings from CSV
        # We'll read the detailed findings CSV if it exists
        # For now, combine the queues
        all_findings = []

        # Add 3-day queue
        for finding in report_data.get('three_day_action_queue', []):
            tier = finding['tier']
            status = 'OVERDUE' if tier['days_remaining'] < 0 else 'ACTIVE'
            all_findings.append([
                finding['asset_name'],
                finding['asset_id'],
                finding['cve_id'],
                finding['plugin_id'],
                finding['plugin_name'],
                'Yes' if finding['in_kev'] else 'No',
                tier['timeline'],
                tier['timeline_days'],
                'Yes' if tier['forensic_triage_required'] else 'No',
                tier['trigger_date'],
                tier['deadline'],
                tier['days_remaining'],
                tier['matched_row'],
                status
            ])

        writer.writerows(all_findings)


def generate_enhanced_json(report_data, output_file):
    """Generate enhanced JSON with summary statistics."""
    enhanced = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "report_type": "BOD 26-04 Risk Tiering",
            "version": "1.0"
        },
        "executive_summary": {
            "critical_action_items": len(report_data['three_day_action_queue']),
            "forensic_triage_required": len(report_data['forensic_triage_required']),
            "overdue_items": sum(1 for f in report_data['three_day_action_queue']
                                if f['tier']['days_remaining'] < 0),
            "coverage_percentage": report_data['coverage']['coverage_pct'],
            "total_findings": report_data['coverage']['total_findings']
        },
        "tier_distribution": report_data['tier_distribution'],
        "coverage": report_data['coverage'],
        "three_day_action_queue": report_data['three_day_action_queue'],
        "forensic_triage_required": report_data['forensic_triage_required'],
        "deferral_population_count": report_data.get('deferral_population_count', 0)
    }

    with open(output_file, 'w') as f:
        json.dump(enhanced, f, indent=2)


def main():
    if len(sys.argv) < 3:
        print("Usage: python generate_reports.py <input_json> <output_dir>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = Path(sys.argv[2])
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load report data
    with open(input_file, 'r') as f:
        report_data = json.load(f)

    # Generate reports
    text_file = output_dir / "bod_26_04_summary.txt"
    csv_file = output_dir / "bod_26_04_summary.csv"
    json_file = output_dir / "bod_26_04_enhanced.json"

    print("Generating reports...")
    generate_text_report(report_data, text_file)
    print(f"  ✓ Text report: {text_file}")

    generate_csv_summary(report_data, csv_file)
    print(f"  ✓ CSV summary: {csv_file}")

    generate_enhanced_json(report_data, json_file)
    print(f"  ✓ Enhanced JSON: {json_file}")

    print("\nDone!")


if __name__ == "__main__":
    main()
