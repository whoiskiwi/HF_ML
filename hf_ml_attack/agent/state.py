from dataclasses import dataclass, field


@dataclass
class AttackState:
    discovered_services: list[str] = field(default_factory=list)
    gained_shells: list[str] = field(default_factory=list)
    found_credentials: dict[str, str] = field(default_factory=dict)
    compromised_hosts: list[str] = field(default_factory=list)
    exfiltrated_data: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"Discovered services: {self.discovered_services or 'none'}\n"
            f"Gained shells: {self.gained_shells or 'none'}\n"
            f"Found credentials: {self.found_credentials or 'none'}\n"
            f"Compromised hosts: {self.compromised_hosts or 'none'}\n"
            f"Exfiltrated data: {self.exfiltrated_data or 'none'}"
        )
