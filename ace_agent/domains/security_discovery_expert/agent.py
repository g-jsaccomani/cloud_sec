from google.adk import Agent, AgentContext
from tools import run_cloudsec_extraction

agent = Agent(config_path="config.yaml")

@agent.tool
def execute_discovery(context: AgentContext, cloud_provider: str, security_tower: str = "ALL") -> str:
    """
    Active tool exposed to the ACE orchestrator to perform compliance-only posture discovery.
    """
    context.send_progress(f"Starting passive scan on {cloud_provider} for security tower {security_tower}...")
    
    report_data = run_cloudsec_extraction(cloud_provider, security_tower)
    
    if report_data["status"] == "SUCCESS":
        context.send_progress(f"Discovery completed! Posture data is structured and ready for target-state mapping.")
        return f"Discovery finished successfully. Findings summary: {report_data['findings_summary']}"
    else:
        return f"Error during security posture discovery: {report_data['message']}"

if __name__ == "__main__":
    agent.run()
