class ResponseAgent:
    def __init__(self):
        self.playbook_matrix = {
            "1": {
                "threat_name": "Privilege Escalation / Unauthorized Process Spawning",
                "actions": [
                    "Isolate the affected host node from the local network subnet immediately.",
                    "Terminate parent process trees associated with unknown script paths.",
                    "Revoke active temporary access credentials and session tokens for the compromised asset."
                ],
                "verification_cmd": "Get-Process | Where-Object {$_.SI -ne 0} | Select-Object ProcessName, Id"
            },
            "0": {
                "threat_name": "Standard Network Anomaly / Reconnaissance Scan",
                "actions": [
                    "Deploy temporary firewall rules blocking the identified inbound malicious IP address.",
                    "Enable aggressive packet capture (PCAP) inspection limits on the targeted interface.",
                    "Flush local DNS caching maps to clear poisoning vectors."
                ],
                "verification_cmd": "Get-NetFirewallRule -DisplayGroup 'Core Networking'"
            },
            "default": {
                "threat_name": "Unclassified Framework Anomaly Event",
                "actions": [
                    "Flag target node architecture for comprehensive manual administrative review.",
                    "Generate snapshot states of system memory registers for external sandbox evaluation."
                ],
                "verification_cmd": "Get-EventLog -LogName Security -Newest 20"
            }
        }

    def determine_mitigation(self, rca_payload: dict) -> dict:
        """Processes forensic intelligence outputs to formulate risk-aware containment steps."""
        print("[Response Agent] Formulating tactical incident containment strategy...")

        detected_indicators = rca_payload.get("detected_indicators", [])

        compiled_actions = []
        verification_commands = []
        threat_profiles = []

        for indicator in detected_indicators:
            playbook = self.playbook_matrix.get(str(indicator), self.playbook_matrix["default"])
            threat_profiles.append(playbook["threat_name"])
            compiled_actions.extend(playbook["actions"])
            if playbook["verification_cmd"]:
                verification_commands.append(playbook["verification_cmd"])

        if not compiled_actions:
            playbook = self.playbook_matrix["default"]
            threat_profiles.append(playbook["threat_name"])
            compiled_actions.extend(playbook["actions"])
            verification_commands.append(playbook["verification_cmd"])

        response_payload = {
            "status": "mitigation_ready",
            "threat_profiles": list(dict.fromkeys(threat_profiles)),
            "targeted_containment_actions": list(dict.fromkeys(compiled_actions)),
            "verification_execution_scripts": list(dict.fromkeys(verification_commands)),
            "approval_required": True,
            "execution_status": "not_executed",
            "safety_override_status": "Recommendations only; analyst approval required."
        }

        print(f"Mitigation Playbook Formulated for: {response_payload['threat_profiles']}")
        return response_payload


if __name__ == "__main__":
    test_rca_output = {'status': 'success', 'detected_indicators': ['1', '0'], 'blast_radius_severity': 'High'}
    agent = ResponseAgent()
    res = agent.determine_mitigation(test_rca_output)
    print("\nExecution Output Data Block:")
    print(res)
