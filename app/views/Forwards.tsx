import { Column, Row, Scroll, Text } from "@tarve/core";
import { connect, editHost, ui } from "../state/store";
import { Glyph } from "../ui/icons";
import { compact, gutter, Action, IconAction, mono } from "../ui/kit";
import { color, labels, radius } from "../ui/tokens";

/** Every port forward of every host, with its live state when a session to that host is open. */
export function Forwards() {
  const rows = ui.hosts.flatMap(host => (host.data.forwards ?? []).map(rule => ({ host, rule })));
  const live = (hostId: string, local: number) => {
    const sessions = Object.values(ui.sessions).filter(info => info.host === hostId && info.status !== "closed");
    for (const info of sessions) {
      const state = info.forwards.find(forward => forward.label.startsWith(`${local}:`) || forward.label.startsWith(`localhost:${local}`) || forward.label.split(":")[0] === String(local));
      if (state) return state.ok ? "up" : "error";
    }
    return sessions.length ? "starting" : "off";
  };
  return (
    <Scroll flex={1}>
      <Column gap={16} style={{ padding: { top: 22, left: gutter(), right: gutter(), bottom: 28 } }}>
        <Column gap={4}>
          <Row gap={10} align="center">
            <Text size={20} weight={650} color={color.text} style={{ letterSpacing: -0.3 }}>Port forwarding</Text>
            <Text size={13} color={color.faint}>{String(rows.length)}</Text>
          </Row>
          <Text size={13} color={color.muted}>Tunnels come up with a session to their host, like ssh -L. Add them in each host's settings.</Text>
        </Column>
        {rows.length === 0 ? (
          <Column gap={10} align="center" style={{ padding: compact() ? 24 : 48, radius: radius.panel, borderColor: color.line, borderWidth: 1 }}>
            <Glyph name="route" size={22} color={color.faint} />
            <Text size={13} color={color.muted}>No forwards yet. Open a host and add one under Port forwarding.</Text>
          </Column>
        ) : (
          <Column style={{ radius: radius.panel, borderColor: color.line, borderWidth: 1, background: color.panel }}>
            {rows.map(({ host, rule }, index) => {
              const state = live(host.id, rule.local);
              const narrow = compact();
              const tone = state === "up" ? color.ok : state === "error" ? color.danger : state === "starting" ? color.accent : color.faint;
              return (
                <Row key={`${host.id}-${index}`} gap={narrow ? 8 : 14} align="center" style={{ height: 56, padding: { left: 16, right: 10 }, borderColor: color.line, borderWidth: index === rows.length - 1 ? 0 : { bottom: 1 } }}>
                  <Row style={{ width: 8, height: 8, radius: 4, background: tone }} />
                  {narrow ? (
                    // Two lines on a phone: the local port over where it leads.
                    <Column flex={1} gap={3} style={{ minWidth: 0 }}>
                      <Text size={13} weight={600} color={color.text} style={mono}>{`localhost:${rule.local}`}</Text>
                      <Row gap={5} align="center" style={{ minWidth: 0 }}>
                        <Glyph name="route" size={12} color={color.faint} />
                        <Text size={12} color={color.muted} style={{ ...mono, shrink: 1, minWidth: 0, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{`${rule.host}:${rule.port} · ${host.data.name}`}</Text>
                      </Row>
                    </Column>
                  ) : (
                    <>
                      <Text size={13} weight={600} color={color.text} style={{ ...mono, width: 150, shrink: 0 }}>{`localhost:${rule.local}`}</Text>
                      <Glyph name="route" size={14} color={color.faint} />
                      <Text size={13} color={color.muted} style={{ ...mono, flex: 1, minWidth: 0, whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{`${rule.host}:${rule.port}`}</Text>
                    </>
                  )}
                  {narrow ? null : <Row gap={6} align="center" style={{ width: 200 }}>
                    <Row style={{ width: 6, height: 6, radius: 3, background: labels[host.data.color ?? "slate"] ?? labels.slate }} />
                    <Text size={12.5} color={color.muted} style={{ whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{host.data.name}</Text>
                  </Row>}
                  <Text size={12} color={tone} style={{ width: narrow ? undefined : 70, shrink: 0, whiteSpace: "nowrap" }}>{state === "up" ? "Active" : state === "error" ? "Failed" : state === "starting" ? "Starting" : "Off"}</Text>
                  {state === "off" && !narrow ? <Action icon="play" label="Open" onClick={() => connect(host.id)} /> : null}
                  <IconAction icon="pencil" label={`Edit ${host.data.name}`} onClick={() => { ui.view = "hosts"; editHost(host.id); }} />
                </Row>
              );
            })}
          </Column>
        )}
      </Column>
    </Scroll>
  );
}
