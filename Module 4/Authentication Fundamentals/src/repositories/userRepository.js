const prisma = require('../db/prisma');

async function emailExists(email) {
  const user = await prisma.user.findUnique({
    where: { email },
    select: { id: true }
  });
  return Boolean(user);
}

async function findByEmail(email) {
  return prisma.user.findUnique({ where: { email } });
}

async function createUser({ name, email, passwordHash }) {
  // The create path returns only the public fields.
  return prisma.user.create({
    data: { name, email, passwordHash },
    select: { id: true, name: true, email: true }
  });
}

module.exports = { emailExists, findByEmail, createUser };
