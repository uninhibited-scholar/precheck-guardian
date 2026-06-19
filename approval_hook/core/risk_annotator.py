"""Rule-based risk classification for action steps.

The annotator scans a step's tool name, description and parameter values
against an extensible catalogue of regular-expression rules. Each rule carries
a risk level, a human-readable warning and (optionally) a suggested mitigation.

Detection is deliberately conservative: when in doubt it errs toward a *higher*
risk level, because the whole point of an approval gate is to surface danger
rather than hide it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Pattern, Union

from ..models.plan import ActionStep, RiskLevel


@dataclass(frozen=True)
class RiskRule:
    """A single detection rule."""

    name: str
    pattern: Pattern[str]
    level: RiskLevel
    warning: str
    mitigation: str = ""


def _rule(name: str, regex: str, level: RiskLevel, warning: str, mitigation: str = "") -> RiskRule:
    return RiskRule(name, re.compile(regex, re.IGNORECASE), level, warning, mitigation)


def _coerce_level(value: Union[str, RiskLevel]) -> RiskLevel:
    if isinstance(value, RiskLevel):
        return value
    try:
        return RiskLevel[str(value).strip().upper()]
    except KeyError as exc:
        valid = ", ".join(level_.label for level_ in RiskLevel)
        raise ValueError(f"unknown risk level {value!r}; expected one of: {valid}") from exc


def rule_from_dict(spec: Dict[str, Any]) -> RiskRule:
    """Build a :class:`RiskRule` from a plain dict (e.g. parsed YAML/JSON).

    Required keys: ``name``, ``pattern``, ``level``. Optional: ``warning``,
    ``mitigation``.
    """
    missing = [k for k in ("name", "pattern", "level") if k not in spec]
    if missing:
        raise ValueError(f"rule is missing required key(s): {', '.join(missing)}")
    try:
        pattern = re.compile(spec["pattern"], re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"rule {spec['name']!r} has an invalid regex: {exc}") from exc
    return RiskRule(
        name=str(spec["name"]),
        pattern=pattern,
        level=_coerce_level(spec["level"]),
        warning=str(spec.get("warning", "")),
        mitigation=str(spec.get("mitigation", "")),
    )


def load_rules_config(config: Dict[str, Any]) -> List[RiskRule]:
    """Turn a config mapping into a list of rules.

    Shape::

        {"mode": "extend" | "replace",   # default "extend"
         "rules": [ {name, pattern, level, warning?, mitigation?}, ... ]}

    ``extend`` appends to the built-in catalogue; ``replace`` uses only the
    custom rules.
    """
    mode = config.get("mode", "extend")
    if mode not in ("extend", "replace"):
        raise ValueError(f"mode must be 'extend' or 'replace', got {mode!r}")
    custom = [rule_from_dict(r) for r in config.get("rules", [])]
    base = list(DEFAULT_RULES) if mode == "extend" else []
    return base + custom


# --- Rule catalogue ---------------------------------------------------------
# Grouped by category for readability. Extend this list to teach the annotator
# about new dangerous operations.
DEFAULT_RULES: List[RiskRule] = [
    # --- Irreversible file / data destruction (CRITICAL) ---
    _rule("rm_recursive_force", r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-rf|-fr)\b",
          RiskLevel.CRITICAL, "Recursive forced delete — files cannot be recovered.",
          "Double-check the target path; prefer moving to a trash dir."),
    _rule("rm_root", r"\brm\s+-[a-z]*\s+/(?:\s|$)", RiskLevel.CRITICAL,
          "Delete targeting the filesystem root.", "Abort unless this is intentional."),
    _rule("sql_delete", r"\bDELETE\s+FROM\b", RiskLevel.CRITICAL,
          "SQL DELETE removes rows permanently.", "Confirm a WHERE clause is present."),
    _rule("sql_delete_no_where", r"\bDELETE\s+FROM\s+\w+\s*;?\s*$", RiskLevel.CRITICAL,
          "DELETE without a WHERE clause wipes the whole table.", "Add a WHERE filter."),
    _rule("sql_drop_table", r"\bDROP\s+TABLE\b", RiskLevel.CRITICAL,
          "Dropping a table destroys its data and schema.", "Back up the table first."),
    _rule("sql_drop_database", r"\bDROP\s+(DATABASE|SCHEMA)\b", RiskLevel.CRITICAL,
          "Dropping a database destroys everything in it.", "Verify you target the right DB."),
    _rule("sql_truncate", r"\bTRUNCATE\s+TABLE\b", RiskLevel.CRITICAL,
          "TRUNCATE empties a table and cannot be rolled back in many engines.", ""),
    _rule("shutil_rmtree", r"shutil\.rmtree", RiskLevel.CRITICAL,
          "rmtree deletes a directory tree recursively.", "Validate the path variable."),
    _rule("disk_overwrite", r"\bdd\s+if=", RiskLevel.CRITICAL,
          "dd can overwrite raw devices and destroy disks.", ""),
    _rule("mkfs", r"\bmkfs(\.\w+)?\b", RiskLevel.CRITICAL,
          "mkfs formats a filesystem, erasing it.", ""),
    _rule("format_disk", r"\b(format|diskpart)\b", RiskLevel.CRITICAL,
          "Disk formatting erases the target volume.", ""),
    _rule("win_del_force", r"\bdel\s+/[a-z]*[fsq]", RiskLevel.HIGH,
          "Forced Windows delete.", ""),
    _rule("win_rmdir", r"\brmdir\s+/s", RiskLevel.HIGH, "Recursive directory removal.", ""),
    _rule("truncate_redirect", r">\s*/dev/sd", RiskLevel.CRITICAL,
          "Redirecting onto a block device corrupts it.", ""),
    _rule("git_clean", r"\bgit\s+clean\s+-[a-z]*[fdx]", RiskLevel.HIGH,
          "git clean removes untracked files irreversibly.", "Run with --dry-run first."),

    # --- Permission / privilege changes (HIGH/CRITICAL) ---
    _rule("chmod_777", r"\bchmod\s+(-[a-z]*\s+)?[0-7]*7{2,3}\b", RiskLevel.HIGH,
          "chmod 777 grants world write access.", "Use least-privilege permissions."),
    _rule("chmod_recursive", r"\bchmod\s+-R\b", RiskLevel.HIGH,
          "Recursive permission change across a tree.", ""),
    _rule("chown", r"\bchown\b", RiskLevel.HIGH, "Ownership change.", ""),
    _rule("sql_grant", r"\bGRANT\s+(ALL|SUPER|ALL\s+PRIVILEGES)\b", RiskLevel.HIGH,
          "Granting broad database privileges.", "Grant only the needed privileges."),
    _rule("sql_revoke", r"\bREVOKE\b", RiskLevel.HIGH, "Revoking database privileges.", ""),
    _rule("sudo", r"\bsudo\b", RiskLevel.HIGH, "Command runs with elevated privileges.", ""),
    _rule("setuid", r"\bchmod\s+[u]?\+s\b|\bsetuid\b", RiskLevel.HIGH,
          "Setting the setuid bit is a privilege-escalation risk.", ""),
    _rule("win_icacls", r"\bicacls\b", RiskLevel.HIGH, "Windows ACL modification.", ""),

    # --- System control (HIGH/CRITICAL) ---
    _rule("reboot", r"\b(reboot|shutdown|halt|poweroff)\b", RiskLevel.HIGH,
          "Powers off or restarts the host.", ""),
    _rule("kill_signal", r"\bkill\s+-9\b|\bkillall\b|\bpkill\b", RiskLevel.HIGH,
          "Force-killing processes can cause data loss.", ""),
    _rule("systemctl_stop", r"\b(systemctl|service)\s+\w*\s*(stop|disable|mask)\b", RiskLevel.HIGH,
          "Stopping or disabling a system service.", ""),
    _rule("iptables_flush", r"\biptables\s+-F\b|\bufw\s+disable\b", RiskLevel.HIGH,
          "Flushing firewall rules removes network protection.", ""),
    _rule("crontab_remove", r"\bcrontab\s+-r\b", RiskLevel.HIGH,
          "crontab -r deletes all cron jobs.", ""),

    # --- Remote code execution / supply chain (CRITICAL) ---
    _rule("curl_pipe_shell", r"(curl|wget)\b.*\|\s*(sudo\s+)?(sh|bash|zsh|python|node)\b",
          RiskLevel.CRITICAL, "Piping a downloaded script straight into a shell.",
          "Download, read, then run — never pipe to a shell blindly."),
    _rule("eval", r"\beval\s*\(", RiskLevel.HIGH, "Dynamic eval of code.", ""),
    _rule("exec_call", r"\bexec\s*\(", RiskLevel.HIGH, "Dynamic exec of code.", ""),
    _rule("os_system", r"\bos\.system\s*\(", RiskLevel.HIGH, "Arbitrary shell command.", ""),
    _rule("subprocess_shell", r"shell\s*=\s*True", RiskLevel.HIGH,
          "subprocess with shell=True is injection-prone.", "Pass an argv list instead."),
    _rule("pickle_loads", r"\bpickle\.loads?\b", RiskLevel.HIGH,
          "Unpickling untrusted data executes arbitrary code.", ""),
    _rule("python_c", r"\bpython[0-9.]*\s+-c\b", RiskLevel.MEDIUM, "Inline Python execution.", ""),

    # --- Version control / deploy (HIGH) ---
    _rule("git_push_force", r"\bgit\s+push\b.*(--force|-f)\b", RiskLevel.HIGH,
          "Force-push can overwrite remote history.", "Use --force-with-lease."),
    _rule("git_reset_hard", r"\bgit\s+reset\s+--hard\b", RiskLevel.HIGH,
          "Hard reset discards local changes.", ""),
    _rule("git_branch_delete", r"\bgit\s+branch\s+-D\b", RiskLevel.MEDIUM,
          "Force-deleting a branch.", ""),

    # --- Cloud / infra (CRITICAL/HIGH) ---
    _rule("terraform_destroy", r"\bterraform\s+destroy\b", RiskLevel.CRITICAL,
          "terraform destroy tears down managed infrastructure.", ""),
    _rule("kubectl_delete", r"\bkubectl\s+delete\b", RiskLevel.HIGH,
          "Deleting Kubernetes resources.", ""),
    _rule("docker_rm_force", r"\bdocker\s+(rm|rmi)\s+-f\b|\bdocker\s+system\s+prune\b",
          RiskLevel.HIGH, "Force-removing containers/images or pruning.", ""),
    _rule("aws_terminate", r"\baws\b.*\b(terminate-instances|delete-|remove-)\b",
          RiskLevel.HIGH, "Destructive AWS CLI operation.", ""),
    _rule("aws_s3_rb", r"\baws\s+s3\s+(rb|rm)\b.*--(force|recursive)", RiskLevel.CRITICAL,
          "Recursively deleting an S3 bucket/objects.", ""),

    # --- Schema / DDL changes (HIGH) ---
    _rule("sql_alter", r"\bALTER\s+TABLE\b", RiskLevel.HIGH, "Schema alteration.", ""),
    _rule("sql_create_user", r"\bCREATE\s+USER\b", RiskLevel.HIGH, "Creating a DB user.", ""),
    _rule("sql_update", r"\bUPDATE\s+\w+\s+SET\b", RiskLevel.HIGH,
          "SQL UPDATE modifies existing rows.", "Confirm the WHERE clause."),
    _rule("sql_insert", r"\bINSERT\s+INTO\b", RiskLevel.MEDIUM, "SQL INSERT writes rows.", ""),

    # --- Secrets / exfiltration (HIGH) ---
    _rule("read_private_key", r"\.ssh/id_(rsa|ed25519|ecdsa)|private[_-]?key", RiskLevel.HIGH,
          "Touching private key material.", ""),
    _rule("read_env_secrets", r"\bcat\b.*\.env\b|\bprintenv\b", RiskLevel.MEDIUM,
          "Reading environment/secret files.", ""),
    _rule("aws_credentials", r"\.aws/credentials|AKIA[0-9A-Z]{16}", RiskLevel.HIGH,
          "Handling AWS credentials.", ""),

    # --- Network writes (MEDIUM) ---
    _rule("http_write", r"\b(POST|PUT|PATCH|DELETE)\b.*\bhttps?://", RiskLevel.MEDIUM,
          "Outbound state-changing HTTP request.", ""),
    _rule("rsync_delete", r"\brsync\b.*--delete", RiskLevel.HIGH,
          "rsync --delete removes files at the destination.", ""),
    _rule("scp_send", r"\bscp\b|\bnc\b|\bnetcat\b", RiskLevel.MEDIUM,
          "Transferring data over the network.", ""),

    # --- Supply chain / package installs (MEDIUM/HIGH) ---
    _rule("pip_install", r"\bpip[0-9]?\s+install\b", RiskLevel.MEDIUM,
          "Installing a Python package runs its setup code.", "Pin the version and verify the source."),
    _rule("pip_extra_index", r"--(extra-)?index-url\b", RiskLevel.HIGH,
          "Custom package index — dependency-confusion risk.", "Confirm the index is trusted."),
    _rule("npm_global", r"\bnpm\s+(install|i)\s+(-g|--global)\b", RiskLevel.MEDIUM,
          "Global npm install affects the whole machine.", "Prefer a local install."),
    _rule("npx_run", r"\bnpx\s+", RiskLevel.MEDIUM,
          "npx downloads and runs a package immediately.", ""),
    _rule("other_pkg_install", r"\b(gem|cargo|go|brew|apt|apt-get|yum|dnf|pacman)\s+install\b",
          RiskLevel.MEDIUM, "Installing a system/language package.", ""),

    # --- Obfuscated / covering-tracks (HIGH/CRITICAL) ---
    _rule("base64_exec", r"\bbase64\s+(-d|--decode)\b.*\|\s*(sh|bash|python)",
          RiskLevel.CRITICAL, "Decoding then executing data hides what runs.", ""),
    _rule("fork_bomb", r":\(\)\s*\{\s*:\|:&\s*\}\s*;:", RiskLevel.CRITICAL,
          "Classic fork bomb — will exhaust the system.", ""),
    _rule("clear_history", r"\bhistory\s+-c\b|\b>\s*~?/?\.bash_history\b", RiskLevel.MEDIUM,
          "Clearing shell history can hide actions.", ""),
    _rule("chattr_immutable", r"\bchattr\s+[+-]i\b", RiskLevel.HIGH,
          "Changing immutable file attributes.", ""),

    # --- Mass data mutation without a filter (CRITICAL) ---
    _rule("update_no_where", r"\bUPDATE\s+\w+\s+SET\b(?!.*\bWHERE\b)", RiskLevel.CRITICAL,
          "UPDATE without a WHERE clause rewrites every row.", "Add a WHERE filter."),
    _rule("sql_drop_other", r"\bDROP\s+(INDEX|VIEW|TRIGGER|PROCEDURE|FUNCTION)\b",
          RiskLevel.HIGH, "Dropping a database object.", ""),

    # --- PowerShell / Windows destructive (HIGH/CRITICAL) ---
    _rule("ps_remove_recurse", r"\bRemove-Item\b.*-Recurse\b.*-Force\b|\bRemove-Item\b.*-Force\b.*-Recurse\b",
          RiskLevel.CRITICAL, "Recursive forced delete (PowerShell).", ""),
    _rule("ps_format_volume", r"\bFormat-Volume\b|\bClear-Disk\b", RiskLevel.CRITICAL,
          "Formatting/clearing a disk (PowerShell).", ""),
    _rule("ps_stop_computer", r"\b(Stop|Restart)-Computer\b", RiskLevel.HIGH,
          "Shutting down or restarting (PowerShell).", ""),

    # --- Python file/process operations (MEDIUM/HIGH) ---
    _rule("py_os_remove", r"\bos\.(remove|unlink|rmdir)\s*\(|\bPath\([^)]*\)\.unlink\b",
          RiskLevel.HIGH, "Python file deletion.", ""),
    _rule("py_subprocess", r"\bsubprocess\.(call|run|Popen|check_output)\b", RiskLevel.MEDIUM,
          "Spawning a subprocess.", ""),
    _rule("py_requests_write", r"\brequests\.(post|put|patch|delete)\s*\(", RiskLevel.MEDIUM,
          "State-changing HTTP request (requests).", ""),

    # --- Cloud project / account deletion (CRITICAL) ---
    _rule("gcloud_delete", r"\bgcloud\s+\w+[\w-]*\s+delete\b|\bgcloud\s+projects\s+delete\b",
          RiskLevel.CRITICAL, "Deleting a GCP resource/project.", ""),
    _rule("az_group_delete", r"\baz\s+group\s+delete\b|\baz\s+\w+\s+delete\b", RiskLevel.HIGH,
          "Deleting an Azure resource/group.", ""),
    _rule("iam_policy", r"\baws\s+iam\s+(create|attach|put)-", RiskLevel.HIGH,
          "Modifying IAM policies/permissions.", "Review the policy scope carefully."),

    # --- Read-only / benign (LOW) ---
    # These never lower a higher-risk match (the annotator takes the max), but
    # they let obviously read-only steps be auto-approved instead of defaulting
    # to MEDIUM.
    _rule("sql_select", r"\bSELECT\b.+\bFROM\b", RiskLevel.LOW, "", ""),
    _rule("read_only", r"\b(cat|less|head|tail|ls|dir|read|show|describe|"
                       r"get|list|fetch|view|print|echo|grep|find)\b", RiskLevel.LOW, "", ""),
]


class RiskAnnotator:
    """Classifies steps by scanning text against :data:`DEFAULT_RULES`."""

    def __init__(self, rules: List[RiskRule] | None = None) -> None:
        self.rules = list(rules) if rules is not None else list(DEFAULT_RULES)

    def add_rule(self, rule: RiskRule) -> None:
        self.rules.append(rule)

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "RiskAnnotator":
        """Build an annotator from a parsed config mapping (see ``load_rules_config``)."""
        return cls(load_rules_config(config))

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "RiskAnnotator":
        """Build an annotator from a JSON or YAML rules file.

        JSON works out of the box (stdlib). YAML (``.yaml``/``.yml``) requires
        the optional ``pyyaml`` dependency.
        """
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in (".yaml", ".yml"):
            try:
                import yaml
            except ImportError as exc:  # pragma: no cover - depends on env
                raise ImportError(
                    "Reading YAML rule files requires PyYAML. Install it with:\n"
                    '    pip install "precheck-guardian[yaml]"'
                ) from exc
            config = yaml.safe_load(text) or {}
        else:
            config = json.loads(text)
        if not isinstance(config, dict):
            raise ValueError("rules config must be a mapping with a 'rules' key")
        return cls.from_config(config)

    def _haystack(self, step: ActionStep) -> str:
        param_text = " ".join(f"{k} {v}" for k, v in step.tool_params.items())
        return " ".join([step.tool_name, step.title, step.description, param_text])

    def matched_rules(self, step: ActionStep) -> List[RiskRule]:
        haystack = self._haystack(step)
        return [rule for rule in self.rules if rule.pattern.search(haystack)]

    def annotate_step(self, step: ActionStep) -> ActionStep:
        """Mutate *step* in place with risk level, warnings and mitigations."""
        matches = self.matched_rules(step)
        if matches:
            step.risk_level = max(rule.level for rule in matches)
            step.matched_rules = [rule.name for rule in matches]
            # Preserve order, de-duplicate warnings/mitigations.
            seen_w, seen_m = set(), set()
            for rule in matches:
                if rule.warning and rule.warning not in seen_w:
                    step.warnings.append(rule.warning)
                    seen_w.add(rule.warning)
                if rule.mitigation and rule.mitigation not in seen_m:
                    step.mitigations.append(rule.mitigation)
                    seen_m.add(rule.mitigation)
            if step.risk_level is RiskLevel.CRITICAL:
                step.can_be_interrupted = False
        return step

    def annotate_plan(self, plan) -> None:
        for step in plan.steps:
            self.annotate_step(step)
