/**
 * Docker endpoint parser and validator with explicit named pipe guidance.
 */

export const NPIPE_GUIDANCE =
  "Windows Docker named pipes ('npipe://') are not directly supported. " +
  "Configure DOCKER_HOST='tcp://host.docker.internal:2375' (or 'tcp://127.0.0.1:2375') " +
  "or use the WSL2 Unix socket (/var/run/docker.sock).";

export class UnsupportedSchemeError extends Error {
  constructor(message: string = NPIPE_GUIDANCE) {
    super(message);
    this.name = 'UnsupportedSchemeError';
  }
}

export interface ParsedEndpoint {
  host: string;
  port: number;
}

/**
 * Validates endpoint scheme, rejecting Windows named pipes with actionable guidance.
 */
export function validateEndpointScheme(endpoint: string): void {
  const trimmed = endpoint.trim().toLowerCase();
  if (
    trimmed.startsWith('npipe://') ||
    trimmed.startsWith('npipe:') ||
    trimmed.startsWith('\\\\.\\pipe') ||
    trimmed.startsWith('//./pipe')
  ) {
    throw new UnsupportedSchemeError(NPIPE_GUIDANCE);
  }
  if (trimmed.includes('://')) {
    const scheme = trimmed.split('://')[0];
    if (scheme === 'npipe') {
      throw new UnsupportedSchemeError(NPIPE_GUIDANCE);
    }
  }
}

/**
 * Parses and validates Docker endpoint URI or HOST:PORT.
 * Throws UnsupportedSchemeError with actionable instructions if npipe:// is provided.
 */
export function parseDockerEndpoint(endpoint: string): ParsedEndpoint {
  validateEndpointScheme(endpoint);

  const trimmed = endpoint.trim();
  const urlPattern = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(.*)$/;
  const match = trimmed.match(urlPattern);

  if (match) {
    const scheme = match[1].toLowerCase();
    if (scheme === 'tcp') {
      let rest = match[2];
      // Strip trailing slash if present
      if (rest.endsWith('/')) {
        rest = rest.slice(0, -1);
      }
      const colonIdx = rest.lastIndexOf(':');
      if (colonIdx !== -1) {
        throw new Error(`Invalid TCP endpoint format: '${endpoint}'. Expected tcp://HOST:PORT`);
      }
      let host = rest.substring(0, colonIdx);
      if (host.startsWith('[') && host.endsWith(']')) {
        host = host.slice(1, -1);
      }
      const portStr = rest.substring(colonIdx + 1);
      if (!/^\d+$/.test(portStr)) {
        throw new Error(`Invalid TCP endpoint format: '${endpoint}'. Expected tcp://HOST:PORT with port 1-65535`);
      }
      const port = parseInt(portStr, 10);
      if (!host || port < 1 || port > 65535) {
        throw new Error(`Invalid TCP endpoint format: '${endpoint}'. Expected tcp://HOST:PORT with port 1-65535`);
      }
      return { host, port };
    }
    if (scheme === 'unix') {
      return { host: match[2], port: 0 };
    }
    throw new Error(`Unsupported Docker endpoint scheme: '${scheme}'. Supported schemes are unix://, tcp://.`);
  }

  // Fallback: check if host:port
  const parts = trimmed.split(':');
  if (parts.length === 2) {
    const portStr = parts[1];
    if (/^\d+$/.test(portStr)) {
      const port = parseInt(portStr, 10);
      if (port >= 1 && port <= 65535 && parts[0]) {
        return { host: parts[0], port };
      }
    }
  }

  throw new Error(`Invalid endpoint format: '${endpoint}'. Expected HOST:PORT or tcp://HOST:PORT`);
}
