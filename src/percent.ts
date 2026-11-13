function decodeAsciiPercent(value: string): string {
  return value.replace(/%([0-9A-Fa-f]{2})/g, (all, hex: string) => {
    const code = Number.parseInt(hex, 16);
    return code > 127 ? all : String.fromCharCode(code);
  });
}

export function percentDecoded(value: string): string | null {
  if (!/%[0-9A-Fa-f]{2}/.test(value)) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    decoded = decodeAsciiPercent(value);
  }
  return decoded === value ? null : decoded;
}

export function includePercentDecoded(strings: string[]): string[] {
  const extra: string[] = [];
  for (const s of strings) {
    const decoded = percentDecoded(s);
    if (decoded !== null) extra.push(decoded);
  }
  return extra.length === 0 ? strings : strings.concat(extra);
}
