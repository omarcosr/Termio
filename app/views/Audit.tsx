import { Column, Modal, Pressable, Row, Scroll, Select, Text, clipboard, viewport } from "@tarve/core";
import { AUDIT_CATEGORIES, auditCategoryOn, refresh, runAudit, toast, ui, type AuditFinding, type AuditReport, type AuditRun, type AuditSeverity } from "../state/store";
import { Glyph } from "../ui/icons";
import { Action, compact, dialogWidth, Hint, IconAction, mono, relativeTime } from "../ui/kit";
import { color, radius } from "../ui/tokens";
import { openSettingsPage } from "./Settings";
import { t } from "../i18n";
import { message, type Message } from "../i18n/messages";

const SEVERITIES: AuditSeverity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_LABEL = () => ({ critical: t("Critical"), high: t("High"), medium: t("Medium"), low: t("Low"), info: t("Info") });
const SEVERITY_HINT = () => ({
  critical: t("Exploitable now or already a backdoor: fix today."),
  high: t("A likely way in or up to root: fix this week."),
  medium: t("Weakens the server: plan it."),
  low: t("Hardening worth doing."),
  info: t("Inventory to review, nothing wrong by itself."),
});
const CATEGORY_LABEL = (): Record<string, string> => ({ base: t("Audit"), cve: "CVEs", ...Object.fromEntries(AUDIT_CATEGORIES.map(item => [item.value, t(item.label)])) });

/** Where a finding comes from, in words. */
function sourceLabel(finding: AuditFinding, report: AuditReport): string {
  switch (finding.source) {
    case "osv": return "OSV.dev";
    case "osv-approx": return t("OSV.dev · {approximate} data", { approximate: report.cve.approximate ?? t("approximate") });
    case "vendor": return t("Distribution advisory");
    default: return t("Server check");
  }
}

export function severityTint(severity: AuditSeverity): string {
  return severity === "critical" || severity === "high" ? color.danger : severity === "medium" ? color.warn : severity === "low" ? color.accent : color.faint;
}

/** The worst severity a report found, ignoring info. */
export function worstSeverity(report: AuditReport): AuditSeverity | undefined {
  return SEVERITIES.find(severity => severity !== "info" && (report.counts[severity] ?? 0) > 0);
}

/** What the open report shows: a severity, a category, and which findings are expanded. */
let severityFilter: AuditSeverity | "all" = "all";
let categoryFilter = "all";
let shownFor: string | undefined;
const expanded = new Set<string>();

/** Opens one finding (the UI check uses it). */
export function expandForTest(id: string): void {
  expanded.add(id);
}

function Badge({ severity }: { severity: AuditSeverity }) {
  const strong = severity === "critical";
  return (
    <Row style={{ width: 66, height: 20, shrink: 0, radius: 5, align: "center", justify: "center", background: strong ? color.danger : "transparent", borderColor: severityTint(severity), borderWidth: 1 }}>
      <Text size={10.5} weight={700} color={strong ? color.canvas : severityTint(severity)}>{SEVERITY_LABEL()[severity].toUpperCase()}</Text>
    </Row>
  );
}

function Block({ label, text, copy }: { label: string; text: string; copy?: boolean }) {
  return (
    <Column gap={5}>
      <Row align="center" justify="between">
        <Text size={11} weight={650} color={color.faint}>{label}</Text>
        {copy ? <IconAction icon="copy" size={22} label={t("Copy {label}", { label: label.toLowerCase() })} onClick={() => { void clipboard.writeText(text).then(() => toast(t("Copied"))); }} /> : null}
      </Row>
      <Text size={11.5} color={color.muted} style={{ ...mono, whiteSpace: "pre-wrap", padding: 10, radius: 7, background: color.canvas, borderColor: color.line, borderWidth: 1 }}>{text}</Text>
    </Column>
  );
}

function FindingRow({ finding, report }: { finding: AuditFinding; report: AuditReport }) {
  const open = expanded.has(finding.id);
  return (
    <Column style={{ borderColor: color.line, borderWidth: { bottom: 1 } }}>
      <Pressable
        focusable
        onClick={() => { if (open) expanded.delete(finding.id); else expanded.add(finding.id); refresh(); }}
        style={{ direction: "row", align: "center", gap: 12, minHeight: 44, padding: { top: 8, bottom: 8, left: 6, right: 6 }, radius: 6, cursor: "pointer", hover: { background: color.hover }, focusVisible: { outlineWidth: 2, outlineColor: color.accent } }}
      >
        <Badge severity={finding.severity} />
        <Text size={13} weight={550} color={color.text} style={{ flex: 1, minWidth: 0 }}>{message(finding.messages?.title ?? finding.title)}</Text>
        {compact() ? null : <Text size={11.5} color={color.faint} style={{ whiteSpace: "nowrap" }}>{CATEGORY_LABEL()[finding.category] ?? finding.category}</Text>}
        <Glyph name={open ? "x" : "plus"} size={12} color={color.faint} />
      </Pressable>
      {open ? (
        <Column gap={12} style={{ padding: { left: 6, right: 6, bottom: 14, top: 2 } }}>
          {finding.detail ? <Text size={12.5} color={color.muted} style={{ lineHeight: 1.5 }}>{message(finding.messages?.detail ?? finding.detail)}</Text> : null}
          {finding.evidence ? <Block label={t("Evidence")} text={finding.evidence} /> : null}
          {finding.fix ? <Block label={t("How to fix")} text={message(finding.messages?.fix ?? finding.fix)} copy /> : null}
          <Text size={11} color={color.faint}>{t("Source: {source} · {hint}", { source: sourceLabel(finding, report), hint: SEVERITY_HINT()[finding.severity] })}</Text>
        </Column>
      ) : null}
    </Column>
  );
}

/** The report as Markdown, for a ticket or a document. */
function markdown(name: string, report: AuditReport): string {
  const facts = report.facts;
  const lines = [
    `# ${t("Security audit")}: ${name}`,
    "",
    `- ${t("When")}: ${new Date(report.finished).toISOString()}`,
    `- ${t("System")}: ${facts.os ?? "?"}, ${t("kernel")} ${facts.kernel ?? "?"} (${facts.arch ?? "?"})`,
    `- ${t("As")}: ${facts.user ?? "?"}${facts.root ? ` ${t("with root")}` : ` ${t("without root (partial)")}`}`,
    `- ${t("Score")}: ${report.score}/100 · ${SEVERITIES.map(severity => `${report.counts[severity] ?? 0} ${SEVERITY_LABEL()[severity].toLowerCase()}`).join(", ")}`,
    "",
  ];
  for (const finding of report.findings) {
    lines.push(`## [${SEVERITY_LABEL()[finding.severity]}] ${message(finding.messages?.title ?? finding.title)}`, "", `${t("Category")}: ${CATEGORY_LABEL()[finding.category] ?? finding.category} · ${t("Source")}: ${sourceLabel(finding, report)}`, "");
    if (finding.detail) lines.push(message(finding.messages?.detail ?? finding.detail), "");
    if (finding.evidence) lines.push("```", finding.evidence, "```", "");
    if (finding.fix) lines.push(`**${t("Fix")}:** ${message(finding.messages?.fix ?? finding.fix)}`, "");
  }
  return lines.join("\n");
}

function Fact({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <Column gap={2} style={{ minWidth: 150, flex: 1 }}>
      <Text size={10.5} weight={650} color={color.faint}>{label.toUpperCase()}</Text>
      <Text size={12.5} color={tone ?? color.text}>{value}</Text>
    </Column>
  );
}

function cveFact(report: AuditReport): string {
  const cve = report.cve;
  const vendor = cve.vendor ? ` + ${cve.vendor} ${t("from the distribution")}` : "";
  switch (cve.status) {
    case "done": return t("{count} in {packages} packages{vendor}", { count: cve.vulnerabilities, packages: cve.affected, vendor });
    case "off": return cve.vendor ? `${cve.vendor} ${t("from the distribution")} (OSV.dev ${t("off")})` : t("Off: turn on in Settings");
    case "unsupported": return `${t("Not covered by OSV.dev")}${vendor}`;
    case "failed": return `${t("Lookup failed")}${vendor}`;
    default: return cve.status;
  }
}

function Summary({ report }: { report: AuditReport }) {
  const facts = report.facts;
  const score = report.score;
  const scoreTint = score >= 80 ? color.ok : score >= 50 ? color.warn : color.danger;
  return (
    <Column gap={14}>
      <Row gap={16} align="center" style={{ wrap: true }}>
        <Column gap={2} style={{ width: 92 }}>
          <Text size={30} weight={700} color={scoreTint}>{String(score)}</Text>
          <Text size={11} color={color.faint}>{t("score out of 100")}</Text>
        </Column>
        <Row gap={6} flex={1} style={{ wrap: true }}>
          {SEVERITIES.map(severity => {
            const active = severityFilter === severity;
            const count = report.counts[severity] ?? 0;
            return (
              <Pressable key={severity} focusable control={{ role: "button", label: t("Show only {severity} findings", { severity: SEVERITY_LABEL()[severity] }) }} onClick={() => { severityFilter = active ? "all" : severity; refresh(); }} style={{ direction: "column", gap: 2, width: 78, padding: 8, radius: 8, cursor: "pointer", background: active ? color.raised : "transparent", borderColor: active ? severityTint(severity) : color.line, borderWidth: active ? 2 : 1, hover: { background: color.hover } }}>
                <Text size={18} weight={700} color={count > 0 ? severityTint(severity) : color.faint}>{String(count)}</Text>
                <Text size={11} color={color.muted}>{SEVERITY_LABEL()[severity]}</Text>
              </Pressable>
            );
          })}
        </Row>
      </Row>
      <Text size={11.5} color={color.faint}>{t("The score starts at 100 and loses points per finding (critical 15, high 5, medium 2, low 1), each severity capped so a pile of CVEs cannot hide the rest. Pick a box to see only that severity.")}</Text>
      <Row gap={14} style={{ wrap: true, padding: 12, radius: 8, background: color.raised }}>
        <Fact label={t("System")} value={facts.os ?? t("unknown")} />
        <Fact label={t("Kernel")} value={`${facts.kernel ?? "?"}${facts.virtualization ? ` · ${facts.virtualization}` : ""}`} />
        <Fact label={t("Checked as")} value={`${facts.user ?? "?"}${facts.root ? (facts.sudo ? t(" via sudo") : " (root)") : t(": no root, partial")}`} tone={facts.root ? undefined : color.warn} />
        <Fact label={t("Known CVEs")} value={cveFact(report)} />
        <Fact label={t("Last run")} value={t("{time}, took {seconds} s", { time: relativeTime(report.finished), seconds: Math.max(1, Math.round((report.finished - report.started) / 1000)) })} />
      </Row>
    </Column>
  );
}

/** The step the core reports, in the UI language: "Checking ssh…" names the category as Settings does. */
function stepText(step: Message): string {
  const category = step.key === "audit.step.checking" ? step.args?.category : undefined;
  const label = typeof category === "string" ? CATEGORY_LABEL()[category] : undefined;
  return label ? t("Checking {what}…", { what: label }) : message(step);
}

/** The phases of a run, from the id of the step the core reports. */
function phase(step: Message): number {
  switch (step.key) {
    case "audit.step.reading":
    case "audit.step.checking":
      return 1;
    case "audit.step.probing":
    case "audit.step.analysing":
      return 2;
    case "audit.step.cve-matching":
    case "audit.step.cve-reading":
      return 3;
    default:
      return 0;
  }
}

function Progress({ run }: { run: AuditRun }) {
  const cve = ui.auditSettings.cve;
  const steps = [
    { label: t("Connect over SSH"), detail: t("With the host's own login, like a terminal.") },
    { label: t("Run the checks on the server"), detail: t("One read-only script; nothing is written there.") },
    { label: t("Judge the answers here"), detail: ui.auditSettings.probe ? t("On this device, and try the open ports from it.") : t("On this device.") },
    ...(cve ? [{ label: t("Match packages against OSV.dev"), detail: t("Only names and versions leave this device.") }] : []),
  ];
  const current = Math.min(phase(run.step), steps.length - 1);
  return (
    <Column gap={10} style={{ padding: 16, radius: radius.panel, background: color.raised, borderColor: color.line, borderWidth: 1 }}>
      {steps.map((step, index) => {
        const done = index < current;
        const active = index === current;
        return (
          <Row key={step.label} gap={12} align="center">
            <Row style={{ width: 20, height: 20, radius: 10, shrink: 0, align: "center", justify: "center", background: done ? color.ok : active ? color.accentSoft : "transparent", borderColor: done ? color.ok : active ? color.accent : color.lineStrong, borderWidth: 1 }}>
              {done ? <Glyph name="check" size={11} color={color.canvas} strokeWidth={3} /> : active ? <Row style={{ width: 12, height: 12, spin: 800 }}><Glyph name="loader" size={12} color={color.accent} /></Row> : <Text size={10.5} weight={650} color={color.faint}>{String(index + 1)}</Text>}
            </Row>
            <Column gap={1} style={{ flex: 1, minWidth: 0 }}>
              <Text size={13} weight={active ? 650 : 500} color={done || active ? color.text : color.muted}>{step.label}</Text>
              <Text size={11.5} color={color.faint}>{active && run.step.text ? stepText(run.step) : step.detail}</Text>
            </Column>
          </Row>
        );
      })}
    </Column>
  );
}

/** Before the first run: what will happen, with the checks that are on. */
function Intro() {
  const audit = ui.auditSettings;
  const on = AUDIT_CATEGORIES.filter(item => auditCategoryOn(item.value));
  const off = AUDIT_CATEGORIES.filter(item => !auditCategoryOn(item.value));
  const reach = [audit.sudo ? t("sudo -n for root-only reads") : t("no sudo: root-only checks stay partial unless the login is root"), audit.cve ? t("package versions matched against OSV.dev") : t("no CVE lookup on OSV.dev"), audit.probe ? t("open ports tried from this device") : t("no port probing")];
  return (
    <Column gap={14} style={{ padding: 16, radius: radius.panel, background: color.raised, borderColor: color.line, borderWidth: 1 }}>
      <Column gap={4}>
        <Text size={14} weight={650} color={color.text}>{t("Nothing is installed on the server")}</Text>
        <Text size={12.5} color={color.muted} style={{ lineHeight: 1.5 }}>{t("Run audit connects like a terminal, runs one read-only script and judges its answers on this device. Nothing is written on the server, and password hashes and file contents never leave it. It takes from a few seconds to a few minutes.")}</Text>
      </Column>
      <Column gap={6}>
        <Text size={11} weight={650} color={color.faint}>{t("WHAT IT CHECKS")}</Text>
        <Row gap={6} style={{ wrap: true }}>
          {on.map(item => <Text key={item.value} size={12} color={color.text} style={{ padding: { left: 8, right: 8, top: 3, bottom: 3 }, radius: 5, background: color.canvas, borderColor: color.line, borderWidth: 1 }}>{t(item.label)}</Text>)}
          {off.map(item => <Text key={item.value} size={12} color={color.faint} style={{ padding: { left: 8, right: 8, top: 3, bottom: 3 }, radius: 5, borderColor: color.line, borderWidth: 1 }}>{t("{label} (off)", { label: t(item.label) })}</Text>)}
        </Row>
        <Text size={12} color={color.faint} style={{ lineHeight: 1.5 }}>{t("Also: {items}.", { items: reach.join("; ") })}</Text>
      </Column>
      <Row>
        <Action label={t("Change what it checks")} icon="settings" onClick={() => { ui.auditOpen = undefined; openSettingsPage("security"); }} />
      </Row>
    </Column>
  );
}

/** A host's audit at a glance, beside its name: the worst finding or the run in progress. */
export function AuditChip({ hostId }: { hostId: string }) {
  const report = ui.audits[hostId];
  const running = ui.auditRuns[hostId]?.state === "running";
  if (!report && !running) return null;
  const worst = report ? worstSeverity(report) : undefined;
  const tone = running ? color.accent : worst ? severityTint(worst) : color.ok;
  const label = running ? t("Auditing…") : worst ? `${report!.counts[worst]} ${SEVERITY_LABEL()[worst].toLowerCase()}` : t("No issues");
  return (
    <Pressable focusable control={{ role: "button", label: t("Security report: {label}", { label }) }} onClick={() => { ui.auditOpen = hostId; }} style={{ direction: "row", align: "center", gap: 5, height: 22, padding: { left: 7, right: 8 }, radius: 11, cursor: "pointer", borderColor: tone, borderWidth: 1, hover: { background: color.hover } }}>
      {running ? <Row style={{ width: 11, height: 11, spin: 800 }}><Glyph name="loader" size={11} color={tone} /></Row> : <Glyph name="shield" size={11} color={tone} />}
      <Text size={11} weight={600} color={tone} style={{ whiteSpace: "nowrap" }}>{label}</Text>
    </Pressable>
  );
}

/** The audit where a host's session shows: its report badge once there is one, else a shield that opens the audit. */
export function AuditButton({ hostId, size = 24 }: { hostId: string; size?: number }) {
  if (!ui.auditSettings.enabled) return null;
  if (ui.audits[hostId] || ui.auditRuns[hostId]?.state === "running") return <AuditChip hostId={hostId} />;
  return <IconAction icon="shield" size={size} label={t("Security audit of this server")} onClick={() => { ui.auditOpen = hostId; }} />;
}

/** The audit in the host editor: what the last run found and the way to the full report. */
export function AuditCard({ hostId }: { hostId: string }) {
  const report = ui.audits[hostId];
  const running = ui.auditRuns[hostId]?.state === "running";
  const worst = report ? worstSeverity(report) : undefined;
  return (
    <Column gap={12} style={{ minWidth: 0, padding: 16, radius: radius.panel, background: color.raised, borderColor: color.line, borderWidth: 1 }}>
      <Row gap={10} align="center" style={{ minWidth: 0 }}>
        <Row style={{ width: 30, height: 30, shrink: 0, radius: 8, background: color.accentSoft, align: "center", justify: "center" }}>
          <Glyph name="shield" size={16} color={color.accent} />
        </Row>
        <Column gap={2} style={{ flex: 1, minWidth: 0 }}>
          <Text size={13.5} weight={650} color={color.text}>{t("Security audit")}</Text>
          <Text size={12} color={worst ? severityTint(worst) : color.muted}>
            {running ? t("Running now…") : report ? t("Score {score}/100 · {findings} · {time}", { score: report.score, findings: SEVERITIES.filter(severity => severity !== "info" && report.counts[severity]).map(severity => `${report.counts[severity]} ${SEVERITY_LABEL()[severity].toLowerCase()}`).join(", ") || t("no issues"), time: relativeTime(report.finished) }) : t("Read-only checks over SSH; nothing is installed.")}
          </Text>
        </Column>
      </Row>
      <Row gap={8}>
        <Action label={report ? t("Open report") : t("Set up and run")} icon="shield" tone={report ? "quiet" : "primary"} onClick={() => { ui.auditOpen = hostId; }} />
        {report ? <Action label={t("Run again")} icon="refresh" busy={running} onClick={() => runAudit(hostId)} /> : null}
      </Row>
    </Column>
  );
}

/** One host's security report: what it does, its progress, and the findings to filter and copy. */
export function Audit() {
  const hostId = ui.auditOpen;
  if (hostId !== shownFor) {
    shownFor = hostId;
    severityFilter = "all";
    categoryFilter = "all";
    expanded.clear();
  }
  const host = ui.hosts.find(record => record.id === hostId);
  const report = hostId ? ui.audits[hostId] : undefined;
  const run = hostId ? ui.auditRuns[hostId] : undefined;
  const running = run?.state === "running";
  const narrow = compact();
  const width = dialogWidth(860);
  const height = Math.min(700, viewport().height - 48);
  const gutter = narrow ? 16 : 24;
  const enabled = ui.auditSettings.enabled;
  const categories = report ? ["all", ...new Set(report.findings.map(finding => finding.category))] : [];
  const findings = (report?.findings ?? []).filter(finding => (severityFilter === "all" || finding.severity === severityFilter) && (categoryFilter === "all" || finding.category === categoryFilter));
  const name = host?.data.name ?? "server";
  const filtered = severityFilter !== "all" || categoryFilter !== "all";
  return (
    <Modal open={hostId !== undefined} onOpenChange={open => { if (!open) ui.auditOpen = undefined; }} width={width} closeOnOverlay closeOnEscape showClose={false} style={{ maxWidth: "100%", padding: 0, background: color.panel, borderColor: color.lineStrong, borderWidth: 1, radius: 14 }}>
      <Column style={{ width, height, radius: 14, overflow: "hidden" }}>
        <Row align="center" gap={10} style={{ height: 58, shrink: 0, padding: { left: gutter, right: 14 }, borderColor: color.line, borderWidth: { bottom: 1 } }}>
          <Glyph name="shield" size={17} color={color.accent} />
          <Text size={16} weight={650} color={color.text} style={{ flex: 1, whiteSpace: "nowrap", textOverflow: "ellipsis", minWidth: 0 }}>{`${t("Security audit")} · ${name}`}</Text>
          {report && !narrow ? <Action label={t("Copy report")} icon="copy" onClick={() => { void clipboard.writeText(markdown(name, report)).then(() => toast(t("Report copied as Markdown"))); }} /> : null}
          {enabled && hostId ? <Action label={running ? t("Running…") : report ? t("Run again") : t("Run audit")} icon="refresh" tone={report ? "quiet" : "primary"} busy={running} onClick={() => runAudit(hostId)} /> : null}
          <IconAction icon="x" label={t("Close")} onClick={() => { ui.auditOpen = undefined; }} />
        </Row>
        <Scroll flex={1} style={{ minHeight: 0 }}>
          <Column gap={16} style={{ padding: { left: gutter, right: gutter, top: 18, bottom: 20 } }}>
            {!enabled ? (
              <Column gap={10} style={{ padding: 16, radius: radius.panel, background: color.raised }}>
                <Hint tone="danger">{t("The security audit is turned off.")}</Hint>
                <Row><Action label={t("Open Settings › Security")} icon="settings" onClick={() => { ui.auditOpen = undefined; openSettingsPage("security"); }} /></Row>
              </Column>
            ) : null}
            {run?.state === "error" ? (
              <Row gap={10} align="center" style={{ padding: 12, radius: 8, background: color.dangerSoft }}>
                <Glyph name="alert" size={14} color={color.danger} />
                <Text size={12.5} color={color.danger} style={{ flex: 1 }}>{t("The audit failed: {step}", { step: message(run.step) })}</Text>
              </Row>
            ) : null}
            {running ? <Progress run={run} /> : null}
            {report ? (
              <Column gap={16}>
                {running ? <Text size={11.5} weight={650} color={color.faint}>{t("THE LAST REPORT, UNTIL THIS RUN ENDS")}</Text> : null}
                <Summary report={report} />
                <Row gap={10} align="center" style={{ wrap: true }}>
                  <Select style={{ width: narrow ? "100%" : 200 }} id="audit-category" value={categoryFilter} options={categories.map(category => ({ value: category, label: category === "all" ? t("Every category") : CATEGORY_LABEL()[category] ?? category }))} onValueChange={value => { categoryFilter = value; refresh(); }} />
                  <Text size={12} color={color.faint} style={{ flex: 1 }}>{t("{shown} of {total} findings · select one for its evidence and fix", { shown: findings.length, total: report.findings.length })}</Text>
                  {filtered ? <Action label={t("Show all")} onClick={() => { severityFilter = "all"; categoryFilter = "all"; refresh(); }} /> : null}
                </Row>
                <Column>{findings.map(finding => <FindingRow key={finding.id} finding={finding} report={report} />)}</Column>
              </Column>
            ) : enabled && !running ? <Intro /> : null}
          </Column>
        </Scroll>
      </Column>
    </Modal>
  );
}
