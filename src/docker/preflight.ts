import * as fs from 'node:fs';
import * as net from 'node:net';

export interface SocketDiagnosis {
  ok: boolean;
  message?: string;
  error?: string;
}

export const NPIPE_GUIDANCE =
  "Windows Docker named pipes ('npipe://') are not directly supported. " +
  "Configure DOCKER_HOST='tcp://host.docker.internal:2375' (or 'tcp://127.0.0.1:2375') " +
  "or use the WSL2 Unix socket (/var/run/docker.sock).";

/**
 * Checks if a target represents a Windows named pipe.
 */
function isNamedPipe(target: string): boolean {
  const s = target.trim().toLowerCase();
  return (
    s.startsWith('npipe://') ||
    s.startsWith('npipe:') ||
    s.startsWith('\\\\.\\pipe') ||
    s.startsWith('//./pipe')
  );
}

/**
 * Preflight diagnosis for Docker daemon socket reachability.
 *
 * Performs filesystem stat/permission validation and an active socket connection
 * probe (with short timeout) to detect stopped (ECONNREFUSED) or unresponsive Docker daemons,
 * returning an explicit, actionable diagnosis message.
 *
 * @param socketPath Path or URI to Docker socket (defaults to DOCKER_SOCKET or DOCKER_HOST or /var/run/docker.sock)
 * @param timeoutMs Active connection probe timeout in milliseconds (defaults to 2000ms)
 * @returns An actionable diagnosis string if unreachable, or null if healthy.
 */
export async function diagnoseSocketAccess(
  socketPath?: string,
  timeoutMs: number = 2000
): Promise<string | null> {
  const envDockerHost = (process.env.DOCKER_HOST || '').trim();
  const envDockerSocket = (process.env.DOCKER_SOCKET || '').trim();

  // If argument is given, prioritize it; otherwise use env variables or default path
  const rawTarget = socketPath ? socketPath.trim() : (envDockerSocket || envDockerHost || '/var/run/docker.sock');

  // Check for Windows Docker named pipes
  if (isNamedPipe(rawTarget) || (envDockerHost && isNamedPipe(envDockerHost))) {
    return NPIPE_GUIDANCE;
  }

  // Handle tcp:// endpoints
  if (rawTarget.toLowerCase().startsWith('tcp://')) {
    let host = '127.0.0.1';
    let port = 2375;
    try {
      const url = new URL(rawTarget);
      host = url.hostname || '127.0.0.1';
      if (host.startsWith('[') && host.endsWith(']')) {
        host = host.slice(1, -1);
      }
      port = url.port ? parseInt(url.port, 10) : 2375;
    } catch {
      const rest = rawTarget.substring(6);
      const colonIdx = rest.lastIndexOf(':');
      if (colonIdx !== -1) {
        host = rest.substring(0, colonIdx) || '127.0.0.1';
        port = parseInt(rest.substring(colonIdx + 1), 10) || 2375;
      }
    }

    return new Promise<string | null>((resolve) => {
      let settled = false;
      const finish = (msg: string | null) => {
        if (!settled) {
          settled = true;
          try {
            socket.destroy();
          } catch {}
          resolve(msg);
        }
      };

      let socket: net.Socket;
      try {
        socket = net.createConnection({ host, port });
      } catch (err: any) {
        finish(`Failed to connect to Docker daemon at ${host}:${port}: ${err.message}`);
        return;
      }

      socket.setTimeout(timeoutMs);

      socket.on('connect', () => {
        finish(null);
      });

      socket.on('error', (err: any) => {
        if (err.code === 'ECONNREFUSED') {
          finish(
            `Docker daemon at ${host}:${port} is stopped or not accepting connections (connection refused). ` +
            "Start the Docker daemon and retry."
          );
        } else {
          finish(
            `Active connection probe to Docker daemon at ${host}:${port} failed: ${err.message} (${err.code || 'unknown'})`
          );
        }
      });

      socket.on('timeout', () => {
        finish(
          `Connection to Docker daemon at ${host}:${port} timed out after ${timeoutMs}ms. ` +
          "The daemon may be hung or blocked by firewall."
        );
      });
    });
  }

  // Handle unix:// prefix
  let targetPath = rawTarget;
  if (targetPath.toLowerCase().startsWith('unix://')) {
    targetPath = targetPath.substring(7);
  }

  // 1. Filesystem existence and socket type check
  try {
    const stats = await fs.promises.stat(targetPath);
    if (!stats.isSocket()) {
      return `Path '${targetPath}' exists but is not a valid UNIX socket.`;
    }
  } catch (err: any) {
    if (err.code === 'ENOENT') {
      return (
        `Docker socket not found at '${targetPath}'. ` +
        "Ensure Docker Engine or Docker Desktop is installed and running."
      );
    }
    if (err.code === 'EACCES') {
      return (
        `Permission denied accessing Docker socket at '${targetPath}'. ` +
        "Check user permissions or docker group membership."
      );
    }
    return `Filesystem error accessing Docker socket at '${targetPath}': ${err.message}`;
  }

  // Check read and write permissions
  try {
    await fs.promises.access(targetPath, fs.constants.R_OK | fs.constants.W_OK);
  } catch (err: any) {
    return (
      `Permission denied for Docker socket '${targetPath}'. ` +
      "Ensure your user has read and write permissions to the socket."
    );
  }

  // 2. Active socket connection probe
  return new Promise<string | null>((resolve) => {
    let settled = false;
    const finish = (msg: string | null) => {
      if (!settled) {
        settled = true;
        try {
          socket.destroy();
        } catch {}
        resolve(msg);
      }
    };

    let socket: net.Socket;
    try {
      socket = net.createConnection({ path: targetPath });
    } catch (err: any) {
      finish(`Active connection probe to Docker socket '${targetPath}' failed: ${err.message}`);
      return;
    }

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      finish(null); // Active connection succeeded; daemon is actively accepting requests.
    });

    socket.on('error', (err: any) => {
      if (err.code === 'ECONNREFUSED') {
        finish(
          `Docker socket exists at '${targetPath}', but the Docker daemon is stopped (connection refused). ` +
          "Start Docker Engine ('systemctl start docker' or start Docker Desktop) and retry."
        );
      } else if (err.code === 'EACCES') {
        finish(
          `Permission denied while connecting to Docker socket '${targetPath}'. ` +
          "Check socket permissions or docker group membership."
        );
      } else {
        finish(
          `Active connection probe to Docker socket '${targetPath}' failed: ${err.message} (${err.code || 'unknown'})`
        );
      }
    });

    socket.on('timeout', () => {
      finish(
        `Connection to Docker socket '${targetPath}' timed out after ${timeoutMs}ms. ` +
        "The Docker daemon may be hung or unresponsive. Restart Docker Engine and retry."
      );
    });
  });
}
