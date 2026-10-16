import type { ClassifyInput, ClassifyResult, LocalInferenceProvider } from '../types.js';

/**
 * Local inference layer (v2 plugin surface).
 *
 * The MVP ships with NO built-in model. This module only defines the contract
 * and a safe runner so that a WebGPU / WASM / ONNX Runtime Web / Transformers.js
 * provider can be dropped in later without changing the router.
 */

/** A provider that is never available; the default when none is configured. */
export const nullInferenceProvider: LocalInferenceProvider = {
  name: 'null',
  isAvailable: () => false,
};

export type InferenceOutcome =
  | { ok: true; result: ClassifyResult; provider: string }
  | { ok: false; reason: 'unavailable' | 'unsupported' | 'timeout' | 'error'; detail?: string };

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`inference-timeout:${ms}ms`)), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

/**
 * Run a provider's `classify` defensively. Never throws: any failure is
 * reported as an `{ ok: false }` outcome so the router can apply its fallback
 * strategy instead of crashing or silently sending raw data to the cloud.
 */
export async function runClassify(
  provider: LocalInferenceProvider | undefined,
  input: ClassifyInput,
  timeoutMs: number,
): Promise<InferenceOutcome> {
  if (!provider) return { ok: false, reason: 'unavailable' };

  let available = false;
  try {
    available = await provider.isAvailable();
  } catch {
    return { ok: false, reason: 'unavailable', detail: 'isAvailable() threw' };
  }
  if (!available) return { ok: false, reason: 'unavailable' };
  if (!provider.classify) return { ok: false, reason: 'unsupported' };

  try {
    const result = await withTimeout(Promise.resolve(provider.classify(input)), timeoutMs);
    return { ok: true, result, provider: provider.name };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.startsWith('inference-timeout')) {
      return { ok: false, reason: 'timeout', detail: message };
    }
    return { ok: false, reason: 'error', detail: message };
  }
}
