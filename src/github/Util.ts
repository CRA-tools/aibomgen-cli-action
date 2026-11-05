import s from "fast-safe-stringify";

export function stringify(o: unknown): string {
  return s(o, undefined, 2);
}
