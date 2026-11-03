import logger from '#config/logger.js';
import bcrypt from 'bcrypt';
import { eq } from 'drizzle-orm';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js';

// Hash password
export const hashPassword = async password => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (e) {
    logger.error('Error hashing password', e);
    throw new Error('Failed to hash password', { cause: e });
  }
};

// Create user
export const createUser = async ({ name, email, password, role = 'user' }) => {
  try {
    // 1. Check if user already exists
    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    // 2. Hash password
    const passwordHash = await hashPassword(password);

    // 3. Insert user into database
    const [newUser] = await db
      .insert(users)
      .values({
        name,
        email,
        password: passwordHash,
        role,
      })
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
      });

    // 4. Return created user
    return newUser;
  } catch (e) {
    logger.error('Error creating user', e);
    throw e;
  }
};

// Sign in user
export const signInUser = async ({ email, password }) => {
  try {
    // 1. Find user by email
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    // Use the same error for unknown email and wrong password
    if (!user) {
      throw new Error('Invalid email or password');
    }

    // 2. Compare the submitted password with the stored hash
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new Error('Invalid email or password');
    }

    // 3. Return user data without the password hash
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    };
  } catch (e) {
    logger.error('Error signing in user', e);
    throw e;
  }
};
