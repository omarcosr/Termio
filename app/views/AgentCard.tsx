import { Column, Row, Text } from "@tarve/core";
import { installAgent, ui } from "../state/store";
import { Glyph, type IconId } from "../ui/icons";
import { Action, mono } from "../ui/kit";
import { color, radius } from "../ui/tokens";

const STEPS = [
  { key: "checking", label: "Check the server" },
  { key: "uploading", label: "Upload termio-agent" },
  { key: "done", label: "Ready" },
] as const;

/** What the agent brings, from the benchmark against plain SSH on a 130 ms, 2 Mbit/s link. */
const GAINS: { icon: IconId; title: string; detail: string }[] = [
  { icon: "activity", title: "Ctrl+C in 0.2 s, not 3.7 s", detail: "A flood of output never clogs the line" },
  { icon: "refresh", title: "Survives drops and sleep", detail: "Reconnects to the same shell over QUIC" },
  { icon: "download", title: "1 KB instead of 1.4 MB", detail: "Sends screens, not every byte of output" },
];

/** Installs termio-agent on a host: what it brings, then each step as it happens. */
export function AgentCard({ hostId }: { hostId: string }) {
  const install = ui.agentInstall[hostId];
  const running = install?.state === "checking" || install?.state === "uploading";
  const reached = install ? STEPS.findIndex(step => step.key === install.state) : -1;
  const tone = install?.state === "error" ? color.danger : install?.state === "done" ? color.ok : color.accent;
  return (
    <Column gap={14} style={{ padding: 16, radius: radius.panel, background: color.raised, borderColor: install?.state === "done" ? color.ok : color.line, borderWidth: 1 }}>
      <Row gap={10} align="center">
        <Row style={{ width: 30, height: 30, radius: 8, background: color.accentSoft, align: "center", justify: "center" }}>
          <Glyph name="shield" size={16} color={color.accent} />
        </Row>
        <Column flex={1} gap={2}>
          <Text size={13.5} weight={650} color={color.text}>termio-agent</Text>
          <Text size={12} color={color.muted}>Resumable sessions built for slow and distant links</Text>
        </Column>
      </Row>

      {install ? (
        <Column gap={8}>
          {STEPS.map((step, index) => {
            const failed = install.state === "error" && index === Math.max(0, STEPS.findIndex(s => s.key === "uploading"));
            const done = install.state === "done" || index < reached;
            const current = index === reached && running;
            return (
              <Row key={step.key} gap={10} align="center">
                <Row style={{ width: 18, height: 18, radius: 9, align: "center", justify: "center", background: done ? color.ok : current ? color.accentSoft : "transparent", borderColor: done ? color.ok : current ? color.accent : color.lineStrong, borderWidth: 1 }}>
                  {done ? <Glyph name="check" size={11} color={color.canvas} strokeWidth={3} /> : failed ? <Glyph name="x" size={10} color={color.danger} strokeWidth={3} /> : null}
                </Row>
                <Text size={12.5} weight={current ? 600 : 500} color={done || current ? color.text : color.faint}>{step.label}</Text>
              </Row>
            );
          })}
          <Text size={12} color={tone} style={install.state === "error" ? {} : mono}>{install.message}</Text>
        </Column>
      ) : (
        <Column gap={8}>
          {GAINS.map(gain => (
            <Row key={gain.title} gap={10} align="center">
              <Glyph name={gain.icon} size={14} color={color.accent} />
              <Column gap={1}>
                <Text size={12.5} weight={600} color={color.text}>{gain.title}</Text>
                <Text size={11.5} color={color.faint}>{gain.detail}</Text>
              </Column>
            </Row>
          ))}
        </Column>
      )}

      <Row gap={10} align="center">
        <Action
          tone={install?.state === "done" ? "quiet" : "primary"}
          icon={install?.state === "done" ? "refresh" : "download"}
          label={running ? "Installing…" : install?.state === "done" ? "Reinstall" : install?.state === "error" ? "Try again" : "Install on this server"}
          disabled={running}
          onClick={() => installAgent(hostId)}
        />
        <Text size={11.5} color={color.faint}>3.6 MB, into ~/.termio/bin. No root needed.</Text>
      </Row>
    </Column>
  );
}
