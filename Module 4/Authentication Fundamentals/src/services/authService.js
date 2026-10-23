const bcrypt = require('bcryptjs');
const userRepository = require('../repositories/userRepository');

const configuredCost = Number.parseInt(process.env.BCRYPT_COST || '12', 10);
const BCRYPT_COST = Number.isInteger(configuredCost) && configuredCost >= 4 && configuredCost <= 31
  ? configuredCost
  : 12;

// Generate a valid dummy bcrypt hash once. Unknown-account attempts still call
// compare, reducing the timing difference between unknown-email and wrong-password failures.
const dummyHashPromise = bcrypt.hash('auth-fundamentals-dummy-credential', BCRYPT_COST);

function appError(statusCode, code, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.code = code;
  return error;
}

function invalidCredentials() {
  return appError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
}

function validateStrings(input, fields) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw appError(400, 'VALIDATION_ERROR', 'Request body must be a JSON object');
  }

  for (const field of fields) {
    if (typeof input[field] !== 'string' || input[field].trim().length === 0) {
      throw appError(400, 'VALIDATION_ERROR', `${field} must be a non-empty string`);
    }
  }
}

function publicUser(user) {
  // Explicit allowlist: never serialize the database record directly.
  return { id: user.id, name: user.name, email: user.email };
}

async function register(input) {
  validateStrings(input, ['name', 'email', 'password']);

  const name = input.name.trim();
  const email = input.email.trim().toLowerCase();
  const password = input.password;

  // Avoid bcrypt work for known duplicate emails. The database unique
  // constraint below remains the final guard for concurrent registrations.
  if (await userRepository.emailExists(email)) {
    throw appError(409, 'EMAIL_EXISTS', 'An account with this email already exists');
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

  try {
    const user = await userRepository.createUser({ name, email, passwordHash });
    return publicUser(user);
  } catch (error) {
    // A concurrent request may win after emailExists() but before createUser().
    if (error && error.code === 'P2002') {
      throw appError(409, 'EMAIL_EXISTS', 'An account with this email already exists');
    }
    throw error;
  }
}

async function login(input) {
  validateStrings(input, ['email', 'password']);

  const email = input.email.trim().toLowerCase();
  const password = input.password;
  const user = await userRepository.findByEmail(email);

  if (!user) {
    await bcrypt.compare(password, await dummyHashPromise);
    throw invalidCredentials();
  }

  const validPassword = await bcrypt.compare(password, user.passwordHash);
  if (!validPassword) {
    throw invalidCredentials();
  }

  return publicUser(user);
}

module.exports = { register, login };
