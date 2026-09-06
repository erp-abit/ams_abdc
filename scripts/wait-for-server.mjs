import net from 'node:net';

const host = '127.0.0.1';
const port = Number(process.env.PORT || 5000);
const retryDelayMs = 200;
const timeoutMs = 30_000;
const startedAt = Date.now();

function waitForServer() {
  const socket = net.createConnection({ host, port });

  socket.once('connect', () => {
    socket.end();
    console.log(`API server is ready on ${host}:${port}`);
  });

  socket.once('error', () => {
    socket.destroy();

    if (Date.now() - startedAt >= timeoutMs) {
      console.error(`Timed out waiting for the API server on ${host}:${port}`);
      process.exitCode = 1;
      return;
    }

    setTimeout(waitForServer, retryDelayMs);
  });
}

waitForServer();
