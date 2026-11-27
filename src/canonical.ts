/**
 * @iris-gate/person – RFC 8785-style canonical JSON (JCS).
 *
 * Produces a deterministic serialisation of a JSON value:
 *
 * - Object keys are sorted recursively at every depth (UTF-16 code unit
 *   order, as RFC 8785 §3.2.3 requires).
 * - No insignificant whitespace.
 * - Strings and numbers use the ECMAScript JSON serialisation, which is what
 *   RFC 8785 §3.2.2 specifies.
 * - Non-finite numbers, BigInt, functions, symbols and circular structures are
 *   rejected (they have no JSON representation).
 * - `undefined` object members are omitted and `undefined` array entries
 *   become `null`, matching `JSON.stringify`.
 * - Values with a `toJSON()` method (e.g. `Date`) are serialised via it.
 *
 * Unlike `JSON.stringify(value, Object.keys(value).sort())`, which silently
 * drops every nested key that is not also a top-level key, this includes the
 * full nested structure in the output.
 */

export function canonicalize(value: unknown): string {
  return serialise(value, new Set());
}

function serialise(value: unknown, seen: Set<object>): string {
  if (value !== null && typeof value === 'object' && typeof (value as { toJSON?: unknown }).toJSON === 'function') {
    value = (value as { toJSON: () => unknown }).toJSON();
  }

  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError('Canonical JSON cannot represent non-finite numbers.');
      }
      return JSON.stringify(value);
    case 'bigint':
      throw new TypeError('Canonical JSON cannot represent BigInt values.');
    case 'undefined':
    case 'function':
    case 'symbol':
      throw new TypeError(`Canonical JSON cannot represent a ${typeof value} value.`);
    default:
      break;
  }

  const obj = value as object;
  if (seen.has(obj)) {
    throw new TypeError('Canonical JSON cannot represent circular structures.');
  }
  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      const items = obj.map((item) =>
        item === undefined || typeof item === 'function' || typeof item === 'symbol'
          ? 'null'
          : serialise(item, seen),
      );
      return `[${items.join(',')}]`;
    }

    const record = obj as Record<string, unknown>;
    const members: string[] = [];
    for (const key of Object.keys(record).sort()) {
      const member = record[key];
      if (member === undefined || typeof member === 'function' || typeof member === 'symbol') {
        continue;
      }
      members.push(`${JSON.stringify(key)}:${serialise(member, seen)}`);
    }
    return `{${members.join(',')}}`;
  } finally {
    seen.delete(obj);
  }
}
