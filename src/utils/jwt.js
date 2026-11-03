import jwt from 'jsonwebtoken';
import logger from '#config/logger.js';

const JWT_SECRET =
  process.env.JWT_SECRET || 'your-secret-key-please-change-in-production';
const JWT_EXPIRE = '1d';

export const jwttocken = {
  sign: payload => {
    try {
      return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRE });
    } catch (e) {
      logger.error('Failed to verify token', e);
      throw new Error('Failed to verify token', { cause: e });
    }
  },

  verify: tocken => {
    try {
      return jwt.verify(tocken, JWT_SECRET);
    } catch (e) {
      logger.error('Failed to verify token', e);
      throw new Error('Failed to verify token', { cause: e });
    }
  },
};
