import type {
  Detector,
  DetectorMatch,
  DetectorName,
  MaskStrategy,
  SensitivityLevel,
} from '../types.js';

/** Options used to build a regex-based detector. */
interface DetectorSpec {
  name: DetectorName;
  level: SensitivityLevel;
  mask: MaskStrategy;
  regex: RegExp;
  /** Optional post-filter to reject false positives (e.g. Luhn check). */
  validate?: (match: string) => boolean;
}

function makeDetector(spec: DetectorSpec): Detector {
  return {
    name: spec.name,
    level: spec.level,
    mask: spec.mask,
    detect(value: string): DetectorMatch[] {
      const matches: DetectorMatch[] = [];
      // Clone the regex so `lastIndex` never leaks between calls.
      const re = new RegExp(spec.regex.source, spec.regex.flags.includes('g') ? spec.regex.flags : spec.regex.flags + 'g');
      let m: RegExpExecArray | null;
      while ((m = re.exec(value)) !== null) {
        const text = m[0];
        if (text.length === 0) {
          re.lastIndex++;
          continue;
        }
        if (spec.validate && !spec.validate(text)) continue;
        matches.push({
          detector: spec.name,
          level: spec.level,
          start: m.index,
          end: m.index + text.length,
          text,
        });
      }
      return matches;
    },
  };
}

/** Luhn checksum, used to reduce bank-card false positives. */
export function luhnValid(digits: string): boolean {
  const cleaned = digits.replace(/\D/g, '');
  if (cleaned.length < 12) return false;
  let sum = 0;
  let alt = false;
  for (let i = cleaned.length - 1; i >= 0; i--) {
    let n = Number(cleaned[i]);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** Rough validity check for a mainland-China 18-digit resident id. */
function isPlausibleIdCard(raw: string): boolean {
  const id = raw.replace(/\s/g, '');
  if (!/^\d{17}[\dXx]$/.test(id)) return false;
  const year = Number(id.slice(6, 10));
  const month = Number(id.slice(10, 12));
  const day = Number(id.slice(12, 14));
  if (year < 1900 || year > new Date().getFullYear()) return false;
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > 31) return false;
  // Weighted checksum (GB 11643-1999).
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  const checks = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += Number(id[i]) * weights[i];
  return checks[sum % 11] === id[17].toUpperCase();
}

const detectorSpecs: DetectorSpec[] = [
  {
    name: 'phone',
    level: 'sensitive',
    mask: 'partial',
    // Mainland-China mobile, tolerant of common separators.
    regex: /(?<!\d)(1[3-9]\d)([\s-]?\d{4})([\s-]?\d{4})(?!\d)/,
  },
  {
    name: 'idCard',
    level: 'critical',
    mask: 'partial',
    regex: /(?<![0-9Xx])\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![0-9Xx])/,
    validate: isPlausibleIdCard,
  },
  {
    name: 'email',
    level: 'sensitive',
    mask: 'partial',
    regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/,
  },
  {
    name: 'bankCard',
    level: 'critical',
    mask: 'partial',
    regex: /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/,
    validate: luhnValid,
  },
  {
    name: 'ipAddress',
    level: 'sensitive',
    mask: 'partial',
    regex: /(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)/,
  },
  {
    name: 'orderNumber',
    level: 'sensitive',
    mask: 'token',
    // Only match order-like codes that carry an explicit label, to avoid FPs.
    regex: /(?:order\s*(?:no|number|#|id)|订单号|订单编号)\s*[:：#]?\s*([A-Za-z0-9-]{6,32})/i,
  },
  {
    name: 'password',
    level: 'forbidden',
    mask: 'full',
    // Secret assignments embedded in free text.
    regex: /(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*\S+/i,
  },
];

/** All built-in detectors, keyed by name. */
export const builtinDetectors: Detector[] = detectorSpecs.map(makeDetector);

/** Look up a built-in detector by name. */
export function getBuiltinDetector(name: DetectorName): Detector | undefined {
  return builtinDetectors.find((d) => d.name === name);
}
