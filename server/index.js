import { createApp } from './app.js';

const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || '127.0.0.1';
const { app } = createApp();
const server = app.listen(port, host, () => {
  console.log(`CITIZEN server listening at http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${server.address().port}`);
  console.log('First-time administrator setup must be completed from the server computer.');
});
