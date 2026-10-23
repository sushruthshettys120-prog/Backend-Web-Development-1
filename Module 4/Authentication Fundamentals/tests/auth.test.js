require('dotenv').config();

const assert = require('node:assert/strict');
const { once } = require('node:events');
const test = require('node:test');
const bcrypt = require('bcryptjs');
const app = require('../src/app');
const prisma = require('../src/db/prisma');

const unique = `${Date.now()}-${process.pid}`;
const email = `auth-fundamentals-${unique}@example.com`;
const unknownEmail = `missing-${unique}@example.com`;
const password = 'correct horse battery staple';

test('authentication endpoints meet the security contract', async (t) => {
  const server = app.listen(0);
  await once(server, 'listening');
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  async function post(path, body) {
    return fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  try {
    await t.test('rejects missing or blank registration fields with 400', async () => {
      const response = await post('/auth/register', {
        name: '  ',
        email,
        password
      });
      assert.equal(response.status, 400);
      assert.equal((await response.json()).error.code, 'VALIDATION_ERROR');
    });

    await t.test('stores a bcrypt hash and returns only public user fields', async () => {
      const response = await post('/auth/register', {
        name: ' Sam ',
        email: `  ${email.toUpperCase()} `,
        password
      });
      assert.equal(response.status, 201);

      const body = await response.json();
      assert.deepEqual(Object.keys(body).sort(), ['email', 'id', 'name']);
      assert.equal(body.name, 'Sam');
      assert.equal(body.email, email);
      assert.equal(Object.hasOwn(body, 'password'), false);
      assert.equal(Object.hasOwn(body, 'passwordHash'), false);

      const savedUser = await prisma.user.findUnique({ where: { email } });
      assert.ok(savedUser);
      assert.notEqual(savedUser.passwordHash, password);
      assert.match(savedUser.passwordHash, /^\$2[aby]\$/);
      assert.equal(await bcrypt.compare(password, savedUser.passwordHash), true);
    });

    await t.test('returns 409 for a duplicate email after normalization', async () => {
      const response = await post('/auth/register', {
        name: 'Another Sam',
        email: email.toUpperCase(),
        password
      });
      assert.equal(response.status, 409);
      assert.equal((await response.json()).error.code, 'EMAIL_EXISTS');
      assert.equal(await prisma.user.count({ where: { email } }), 1);
    });

    await t.test('logs in successfully and returns only public fields', async () => {
      const response = await post('/auth/login', { email: email.toUpperCase(), password });
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.deepEqual(Object.keys(body).sort(), ['email', 'id', 'name']);
      assert.equal(body.email, email);
      assert.equal(Object.hasOwn(body, 'passwordHash'), false);
      assert.equal(Object.hasOwn(body, 'password'), false);
    });

    await t.test('uses byte-for-byte identical 401 JSON for both credential failures', async () => {
      const wrongPasswordResponse = await post('/auth/login', {
        email,
        password: 'not-the-correct-password'
      });
      const unknownEmailResponse = await post('/auth/login', {
        email: unknownEmail,
        password
      });

      assert.equal(wrongPasswordResponse.status, 401);
      assert.equal(unknownEmailResponse.status, 401);
      const wrongPasswordBody = await wrongPasswordResponse.text();
      const unknownEmailBody = await unknownEmailResponse.text();
      assert.equal(wrongPasswordBody, unknownEmailBody);
      assert.equal(wrongPasswordBody, JSON.stringify({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        }
      }));
    });

    await t.test('rejects missing login fields with 400', async () => {
      const response = await post('/auth/login', { email });
      assert.equal(response.status, 400);
      assert.equal((await response.json()).error.code, 'VALIDATION_ERROR');
    });
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
    await prisma.user.deleteMany({ where: { email: { in: [email, unknownEmail] } } });
    await prisma.$disconnect();
  }
});
