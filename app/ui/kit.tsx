import { Column, Input, Pressable, Row, Text, type InputType, type Style } from "@tarve/core";
import { Glyph, type IconId } from "./icons";
import { color, font, radius } from "./tokens";

export const mono: Style = { fontFamily: font.mono };

export function Label({ children }: { children: string }) {
  return <Text size={12} weight={600} color={color.muted}>{children}</Text>;
}

export function Hint({ children, tone = "muted" }: { children: string; tone?: "muted" | "danger" }) {
  return <Text size={12} color={tone === "danger" ? color.danger : color.faint}>{children}</Text>;
}

const inputStyle: Style = {
  height: 34,
  background: color.canvas,
  borderColor: color.line,
  borderWidth: 1,
  radius: radius.control,
  foreground: color.text,
  padding: { left: 10, right: 10 },
  fontSize: 13,
  focus: { borderColor: color.accent, outlineWidth: 0 },
  hover: { borderColor: color.lineStrong },
};

export function Field(props: {
  id?: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  onSubmit?: () => void;
  placeholder?: string;
  type?: InputType;
  hint?: string;
  monospace?: boolean;
  grow?: number;
}) {
  return (
    <Column gap={6} flex={props.grow}>
      <Label>{props.label}</Label>
      <Input
        id={props.id}
        type={props.type}
        value={props.value}
        placeholder={props.placeholder}
        onChange={props.onChange}
        onSubmit={() => props.onSubmit?.()}
        style={props.monospace ? { ...inputStyle, ...mono, fontSize: 12.5 } : inputStyle}
      />
      {props.hint ? <Hint>{props.hint}</Hint> : null}
    </Column>
  );
}

export function TextField(props: { id?: string; value: string; onChange: (value: string) => void; onSubmit?: (value: string) => void; placeholder?: string; type?: InputType; style?: Style }) {
  return <Input id={props.id} type={props.type} value={props.value} placeholder={props.placeholder} onChange={props.onChange} onSubmit={value => props.onSubmit?.(value)} style={{ ...inputStyle, ...props.style }} />;
}

type Tone = "primary" | "quiet" | "danger";

const buttonTones: Record<Tone, Style> = {
  primary: { background: color.accent, foreground: color.accentInk, hover: { background: color.accentHover } },
  quiet: { background: color.raised, foreground: color.text, borderColor: color.line, borderWidth: 1, hover: { background: color.hover, borderColor: color.lineStrong } },
  danger: { background: "transparent", foreground: color.danger, borderColor: color.line, borderWidth: 1, hover: { background: color.dangerSoft, borderColor: color.danger } },
};

export function Action(props: { label: string; onClick: () => void; tone?: Tone; icon?: IconId; disabled?: boolean; shortcut?: string }) {
  const tone = buttonTones[props.tone ?? "quiet"];
  const ink = String(tone.foreground);
  return (
    <Pressable
      onClick={props.disabled ? undefined : props.onClick}
      disabled={props.disabled}
      focusable
      style={{
        height: 34,
        padding: { left: 12, right: 12 },
        radius: radius.control,
        direction: "row",
        align: "center",
        gap: 8,
        opacity: props.disabled ? 0.45 : 1,
        transition: { all: { duration: 120, easing: "easeOut" } },
        focusVisible: { outlineWidth: 2, outlineColor: color.accent },
        ...tone,
      }}
    >
      {props.icon ? <Glyph name={props.icon} size={15} color={ink} /> : null}
      <Text size={13} weight={600} color={ink}>{props.label}</Text>
      {props.shortcut ? <Text size={11} color={props.tone === "primary" ? color.accentInk : color.faint} style={mono}>{props.shortcut}</Text> : null}
    </Pressable>
  );
}

export function IconAction(props: { icon: IconId; label: string; onClick: () => void; size?: number; color?: string }) {
  return (
    <Pressable
      onClick={props.onClick}
      focusable
      control={{ role: "button", label: props.label }}
      style={{
        width: props.size ?? 30,
        height: props.size ?? 30,
        radius: radius.control,
        align: "center",
        justify: "center",
        hover: { background: color.hover },
        focusVisible: { outlineWidth: 2, outlineColor: color.accent },
      }}
    >
      <Glyph name={props.icon} size={15} color={props.color ?? color.muted} />
    </Pressable>
  );
}

/** A two-option or few-option switch, for choices that fit on one line. */
export function Segments<T extends string>(props: { value: T; options: readonly { value: T; label: string }[]; onChange: (value: T) => void }) {
  return (
    <Row style={{ background: color.canvas, borderColor: color.line, borderWidth: 1, radius: radius.control, padding: 3, gap: 2 }}>
      {props.options.map(option => {
        const active = option.value === props.value;
        return (
          <Pressable
            key={option.value}
            onClick={() => props.onChange(option.value)}
            focusable
            style={{
              height: 26,
              padding: { left: 10, right: 10 },
              radius: radius.control - 2,
              align: "center",
              justify: "center",
              background: active ? color.raised : "transparent",
              hover: { background: active ? color.raised : color.hover },
            }}
          >
            <Text size={12} weight={600} color={active ? color.text : color.muted}>{option.label}</Text>
          </Pressable>
        );
      })}
    </Row>
  );
}

export function Divider() {
  return <Row style={{ height: 1, background: color.line }} />;
}

export function relativeTime(at?: number): string {
  if (!at) return "never";
  const seconds = Math.round((Date.now() - at) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  return days < 30 ? `${days} d ago` : new Date(at).toLocaleDateString();
}
