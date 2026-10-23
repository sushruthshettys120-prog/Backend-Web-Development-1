require('dotenv').config();

const express = require('express');
const authRoutes = require('./routes/authRoutes');

const app = express();

app.use(express.json());
app.use('/auth', authRoutes);

// Keep errors controlled: never expose or log raw Prisma/bcrypt details.
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);

  if (error && error.type === 'entity.parse.failed') {
    return res.status(400).json({
      error: {
        code: 'INVALID_JSON',
        message: 'Request body must contain valid JSON'
      }
    });
  }

  const statusCode = Number(error && error.statusCode);
  if (Number.isInteger(statusCode) && statusCode >= 400 && statusCode < 500) {
    return res.status(statusCode).json({
      error: {
        code: error.code || 'BAD_REQUEST',
        message: error.message || 'Request could not be processed'
      }
    });
  }

  console.error('Internal authentication API error');
  return res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }
  });
});

if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => console.log(`API listening on port ${port}`));
}

module.exports = app;
