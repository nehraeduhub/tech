"""Domain/sector-specific penetration-testing recommendations.

A curated knowledge base that maps a target's business sector to the cyber
threats most relevant to it (with India-specific context), the penetration
tests that should be prioritised, and the compliance regimes that typically
apply. Used to enrich the report with actionable, context-aware guidance.

This is advisory content for authorised testing and remediation planning.
"""
from __future__ import annotations

SECTORS = {
    "banking": "Banking / Financial Services / Fintech",
    "government": "Government / Public Sector",
    "healthcare": "Healthcare / Hospitals / Pharma",
    "ecommerce": "E-commerce / Retail",
    "education": "Education / EdTech",
    "it_saas": "IT / SaaS / Technology",
    "telecom": "Telecom / ISP",
    "critical": "Energy / Utilities / Critical Infrastructure",
    "generic": "General / Other",
}

_KB = {
    "banking": {
        "threats": [
            "Credential stuffing & account takeover (ATO)",
            "UPI / payment-flow fraud and logic abuse",
            "API abuse and Broken Object Level Authorization (BOLA/IDOR)",
            "Phishing & mobile-banking trojans (e.g. targeting Indian banks)",
            "Supply-chain and third-party aggregator compromise",
        ],
        "india_context": "Targeted heavily in India. Must align with RBI "
        "cyber-security framework, NPCI/UPI security guidelines and CERT-In "
        "incident-reporting (6-hour rule).",
        "pt_focus": [
            "Authentication: MFA bypass, OTP replay/brute-force, session fixation",
            "Authorization: IDOR on account/transaction IDs, privilege escalation",
            "Payment logic: amount tampering, race conditions, currency/round-off",
            "API security: OWASP API Top 10, mass assignment, rate-limit bypass",
            "Mobile app + backend API pentest (iOS/Android)",
        ],
        "compliance": ["RBI Cyber Security Framework", "PCI-DSS", "CERT-In",
                       "DPDP Act 2023"],
    },
    "government": {
        "threats": [
            "State-sponsored APT intrusion and espionage",
            "Defacement and hacktivism",
            "Data leakage of citizen PII (Aadhaar-linked data)",
            "Outdated/unpatched public portals",
        ],
        "india_context": "Indian government portals are frequent APT and "
        "hacktivist targets. Follow CERT-In guidelines and the Guidelines for "
        "Indian Government Websites (GIGW).",
        "pt_focus": [
            "External network + web app pentest of public portals",
            "Authentication and access control on citizen-service apps",
            "Legacy component and CMS exploitation (known CVEs)",
            "Sensitive data exposure / PII leakage testing",
        ],
        "compliance": ["CERT-In", "GIGW", "DPDP Act 2023", "ISO 27001"],
    },
    "healthcare": {
        "threats": [
            "Ransomware against hospitals (patient-care disruption)",
            "Theft of electronic health records (EHR/PHI)",
            "Insecure medical devices & IoT",
            "Insider misuse of patient data",
        ],
        "india_context": "Indian hospitals have faced major ransomware incidents "
        "(e.g. AIIMS). Align with DPDP Act and ISO 27001; consider HIPAA for "
        "international data.",
        "pt_focus": [
            "Ransomware-readiness: external exposure, RDP/SMB, phishing resilience",
            "EHR application pentest + access controls on patient records (IDOR)",
            "Network segmentation testing (IT/OT/medical devices)",
            "Backup and recovery validation",
        ],
        "compliance": ["DPDP Act 2023", "ISO 27001", "HIPAA (if applicable)",
                       "CERT-In"],
    },
    "ecommerce": {
        "threats": [
            "Payment fraud and card testing",
            "Business-logic abuse (coupon/price/refund manipulation)",
            "Account takeover and credential stuffing",
            "Web skimming / Magecart (malicious JS on checkout)",
            "Bot-driven scraping and inventory hoarding",
        ],
        "india_context": "High-volume Indian retail platforms face card-testing "
        "and logic-abuse fraud. PCI-DSS applies to card handling; DPDP Act to "
        "customer data.",
        "pt_focus": [
            "Business-logic testing: price/amount tampering, coupon abuse, refunds",
            "Payment gateway integration and webhook security",
            "Checkout JS supply-chain (Magecart) and CSP review",
            "Authentication, IDOR on orders/addresses, rate limiting",
        ],
        "compliance": ["PCI-DSS", "DPDP Act 2023", "CERT-In"],
    },
    "education": {
        "threats": [
            "Student/staff PII exposure",
            "Exam/result tampering and grade manipulation",
            "Account takeover on LMS platforms",
            "DDoS during admissions/exams",
        ],
        "india_context": "EdTech and university portals hold large PII sets. DPDP "
        "Act applies; protect minors' data carefully.",
        "pt_focus": [
            "Access control on results/records (IDOR, privilege escalation)",
            "Authentication hardening on LMS and student portals",
            "File upload and assignment-submission abuse",
            "PII exposure and insecure direct downloads",
        ],
        "compliance": ["DPDP Act 2023", "CERT-In", "ISO 27001"],
    },
    "it_saas": {
        "threats": [
            "Multi-tenant data isolation failures",
            "API and OAuth/SSO misconfiguration",
            "CI/CD and secrets exposure",
            "Supply-chain (dependency) compromise",
        ],
        "india_context": "Indian SaaS exporters must meet client security audits "
        "(SOC 2, ISO 27001) and CERT-In; cross-border data flows invoke DPDP Act.",
        "pt_focus": [
            "Tenant isolation / cross-tenant access testing",
            "API security (OWASP API Top 10), authz, rate limiting",
            "SSO/OAuth/JWT flaws, token handling",
            "Secrets in code, exposed CI/CD, cloud misconfiguration",
        ],
        "compliance": ["SOC 2", "ISO 27001", "DPDP Act 2023", "CERT-In"],
    },
    "telecom": {
        "threats": [
            "Signalling (SS7/Diameter) and subscriber data abuse",
            "SIM-swap enabling ATO elsewhere",
            "Large-scale PII and CDR exposure",
            "Core network and OSS/BSS compromise",
        ],
        "india_context": "Telecom is critical infrastructure in India under DoT "
        "and CERT-In oversight; large subscriber PII sets raise DPDP exposure.",
        "pt_focus": [
            "Self-care portal and API pentest (subscriber data, IDOR)",
            "SIM-swap / number-port process abuse testing",
            "OSS/BSS and internal network segmentation",
        ],
        "compliance": ["CERT-In", "DoT security requirements", "DPDP Act 2023"],
    },
    "critical": {
        "threats": [
            "ICS/SCADA intrusion and sabotage",
            "State-sponsored APT targeting of power/water/energy",
            "Ransomware with physical-process impact",
            "Insecure remote access to OT",
        ],
        "india_context": "Power and energy sectors in India have seen APT "
        "targeting. Follow NCIIPC guidance for Critical Information Infrastructure "
        "and CERT-In.",
        "pt_focus": [
            "IT/OT segmentation and remote-access (VPN/jump host) testing",
            "External exposure of ICS/SCADA and HMIs",
            "Phishing and initial-access resilience",
            "Safe, read-only OT assessment (no disruption)",
        ],
        "compliance": ["NCIIPC guidelines", "CERT-In", "IEC 62443", "ISO 27001"],
    },
    "generic": {
        "threats": [
            "Web application exploitation (OWASP Top 10)",
            "Credential attacks and account takeover",
            "Ransomware via phishing and exposed services",
            "Vulnerable/outdated components",
        ],
        "india_context": "All India-facing services should meet CERT-In "
        "directions (incident reporting, log retention) and the DPDP Act 2023.",
        "pt_focus": [
            "Full web application pentest (OWASP WSTG)",
            "External network exposure and service hardening",
            "Authentication and access-control testing",
            "Patch and configuration review",
        ],
        "compliance": ["CERT-In", "DPDP Act 2023", "ISO 27001"],
    },
}

WORLD_TRENDS = [
    "Ransomware-as-a-Service continues to dominate global incident volume.",
    "Exploitation of edge/VPN and public-facing app CVEs is a top initial-access "
    "vector.",
    "API attacks are rising sharply as apps become API-first.",
    "Supply-chain and third-party compromise remain high-impact.",
    "AI-assisted phishing is increasing social-engineering success rates.",
]


def get(sector: str) -> dict:
    kb = _KB.get(sector, _KB["generic"])
    return {
        "sector": SECTORS.get(sector, SECTORS["generic"]),
        "threats": kb["threats"],
        "india_context": kb["india_context"],
        "pt_focus": kb["pt_focus"],
        "compliance": kb["compliance"],
        "world_trends": WORLD_TRENDS,
    }
