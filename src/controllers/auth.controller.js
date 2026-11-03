import logger from '#config/logger.js';
import { signupSchema } from '#validations/auth.validation.js';
import { formatValidationError } from '#utils/format.js';
import { createUser } from '#services/auth.service.js';
import { jwttocken } from '#utils/jwt.js';
import { cookies } from '#utils/cookies.js';
import { signInSchema } from '#validations/auth.validation.js';
import { signInUser } from '#services/auth.service.js';

export const signup = async (req, res, next) => {
  try {
    // 1. Validate incoming data
    const validationResult = signupSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation error',
        details: formatValidationError(validationResult.error),
      });
    }

    // 2. Extract validated data
    const { name, email, password, role } = validationResult.data;

    // 3. Create user in database
    const user = await createUser({
      name,
      email,
      password,
      role,
    });

    // 4. Generate JWT
    const token = jwttocken.sign({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    // 5. Set authentication cookie
    cookies.set(res, 'token', token);

    // 6. Log successful registration
    logger.info(`User registered successfully: ${email}`);

    // 7. Return response
    return res.status(201).json({
      message: 'User registered!',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (e) {
    logger.error('Signup error', e);

    if (e.message === 'User with this email already exists') {
      return res.status(409).json({
        error: 'Email already exists',
      });
    }

    next(e);
  }
};

// Sign in
export const signin = async (req, res, next) => {
  try {
    const validationResult = signInSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation error',
        details: formatValidationError(validationResult.error),
      });
    }

    const user = await signInUser(validationResult.data);

    const token = jwttocken.sign({
      id: user.id,
      email: user.email,
      role: user.role,
    });

    cookies.set(res, 'token', token);

    return res.status(200).json({
      message: 'Signed in successfully',
      user,
    });
  } catch (e) {
    if (e.message === 'Invalid email or password') {
      return res.status(401).json({
        error: 'Invalid email or password',
      });
    }

    logger.error('Signin error', e);
    next(e);
  }
};

// Sign out
export const signout = (req, res) => {
  cookies.clear(res, 'token');

  return res.status(200).json({
    message: 'Signed out successfully',
  });
};
