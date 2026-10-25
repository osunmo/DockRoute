import assert from 'node:assert';
import * as net from 'node:net';
import { diagnoseSocketAccess, NPIPE_GUIDANCE as PREFLIGHT_NPIPE_GUIDANCE } from '../src/docker/preflight';
import {
  parseDockerEndpoint,
  validateEndpointScheme,
  UnsupportedSchemeError,
  NPIPE_GUIDANCE,
} from '../src/docker/endpoint';

async function runTests() {
  console.log('Running TypeScript endpoint and preflight tests...');

  // --- Endpoint Tests ---
  // 1. npipe:// throws UnsupportedSchemeError
  assert.throws(
    () => validateEndpointScheme('npipe:////./pipe/docker_engine'),
    (err: any) => err instanceof UnsupportedSchemeError && err.message.includes("Windows Docker named pipes ('npipe://') are not directly supported")
  );

  // 2. Raw Windows pipe path throws UnsupportedSchemeError
  assert.throws(
    () => validateEndpointScheme('\\\\.\\pipe\\docker_engine'),
    (err: any) => err instanceof UnsupportedSchemeError && err.message.includes(NPIPE_GUIDANCE)
  );

  assert.throws(
    () => validateEndpointScheme('//./pipe/docker_engine'),
    (err: any) => err instanceof UnsupportedSchemeError && err.message.includes(NPIPE_GUIDANCE)
  );

  // 3. parseDockerEndpoint with tcp://
  const tcpEp = parseDockerEndpoint('tcp://127.0.0.1:2375');
  assert.strictEqual(tcpEp.host, '127.0.0.1');
  assert.strictEqual(tcpEp.port, 2375);

  // 4. parseDockerEndpoint with bracketed IPv6
  const ipv6Ep = parseDockerEndpoint('tcp://[::1]:2375');
  assert.strictEqual(ipv6Ep.host, '::1');
  assert.strictEqual(ipv6Ep.port, 2375);

  // 5. parseDockerEndpoint rejects npipe
  assert.throws(
    () => parseDockerEndpoint('npipe:////./pipe/docker_engine'),
    (err: any) => err instanceof UnsupportedSchemeError
  );

  // --- Preflight Tests ---
  // 6. diagnoseSocketAccess with npipe:// directly passed
  const npipeMsg = await diagnoseSocketAccess('npipe:////./pipe/docker_engine');
  assert.strictEqual(npipeMsg, PREFLIGHT_NPIPE_GUIDANCE);

  // 7. diagnoseSocketAccess with raw pipe directly passed
  const rawPipeMsg = await diagnoseSocketAccess('\\\\.\\pipe\\docker_engine');
  assert.strictEqual(rawPipeMsg, PREFLIGHT_NPIPE_GUIDANCE);

  // 8. diagnoseSocketAccess with DOCKER_HOST env
  process.env.DOCKER_HOST = 'npipe:////./pipe/docker_engine';
  const envNpipeMsg = await diagnoseSocketAccess();
  assert.strictEqual(envNpipeMsg, PREFLIGHT_NPIPE_GUIDANCE);
  delete process.env.DOCKER_HOST;

  // 9. diagnoseSocketAccess with nonexistent Unix socket
  const nonexistentMsg = await diagnoseSocketAccess('/nonexistent/path/to/docker.sock');
  assert(nonexistentMsg !== null && nonexistentMsg.toLowerCase().includes('not found'));

  // 10. diagnoseSocketAccess strips unix://
  const unixNonexistent = await diagnoseSocketAccess('unix:///nonexistent/path/to/docker.sock');
  assert(unixNonexistent !== null && unixNonexistent.includes('/nonexistent/path/to/docker.sock'));
  assert(!unixNonexistent.includes('unix://'));

  // 11. diagnoseSocketAccess with stopped TCP daemon
  const tempServer = net.createServer();
  await new Promise<void>((resolve) => tempServer.listen(0, '127.0.0.1', () => resolve()));
  const freePort = (tempServer.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => tempServer.close(() => resolve()));

  const tcpStoppedMsg = await diagnoseSocketAccess(`tcp://127.0.0.1:${freePort}`, 500);
  assert(tcpStoppedMsg !== null && tcpStoppedMsg.toLowerCase().includes('connection refused'));

  console.log('All TypeScript unit tests passed successfully!');
}

runTests().catch((err) => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
