import { NextFunction, Request, Response } from 'express';
import httpResponse from '../util/httpResponse';
import responseMessage from '../constant/responseMessage';
import httpError from '../util/httpError';
import quicker from '../util/quicker';
import { IDecryptedJwt, ILoginRequestBody, IRefreshToken, IRegisterRequestBody, IUser } from '../types/userType';
import { validateJoiSchema, validateLoginBody, validateRegisterBody } from '../service/validationService';
import databaseService from '../service/databaseService';
import { EUserRole } from '../constant/userConstant';
import config from '../config/config';
import emailService from '../service/emailService';
import logger from '../util/logger';
import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import { EApplicationEnvironment } from '../constant/application';

dayjs.extend(utc);

interface IRegisterRequest extends Request {
    body: IRegisterRequestBody;
}
interface ILoginRequest extends Request {
    body: ILoginRequestBody;
}
interface IConfirmRequest extends Request {
    params: { token: string };
    query: { code: string };
}
interface ISelfIdentificationRequest extends Request {
    authenticatedUser: IUser;
}

export default {
    self: (req: Request, res: Response, next: NextFunction) => {
        try {
            httpResponse(req, res, 200, responseMessage.SUCCESS);
        } catch (err) {
            httpError(next, err, req, 500);
        }
    },

    health: (req: Request, res: Response, next: NextFunction) => {
        try {
            const healthData = {
                application: quicker.getApplicationHealth(),
                system: quicker.getSystemHealth(),
                timestamp: Date.now()
            };

            httpResponse(req, res, 200, responseMessage.SUCCESS, healthData);
        } catch (err) {
            httpError(next, err, req, 500);
        }
    },

    register: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { body } = req as IRegisterRequest;

            // TODO: Add Register logic
            // * Body validation
            const { error, value } = validateJoiSchema<IRegisterRequestBody>(validateRegisterBody, body);

            if (error) {
                return httpError(next, error, req, 422);
            }
            // * Phone no parsing and validation
            const { phoneNo, name, consent, email, password } = value;
            const { countryCode, internationalNumber, isoCode } = quicker.parsePhoneNumber('+' + phoneNo);

            if (!countryCode || !isoCode || !internationalNumber) {
                return httpError(next, new Error(responseMessage.INVALID_PHONE_NUMBER), req, 422);
            }

            // * Timzezone
            const timezone = quicker.countryTimezone(isoCode);
            if (!timezone || timezone.length === 0) {
                return httpError(next, new Error(responseMessage.INVALID_PHONE_NUMBER), req, 422);
            }

            // * Check user existence using email address
            const user = await databaseService.findUserByEmail(email);
            if (user) {
                return httpError(next, new Error(responseMessage.ALREADY_EXIST('user', email)), req, 422);
            }

            // * Encrypt password
            const encryptedPassword = await quicker.hashPassword(password);

            // * Account confirmation object data
            const token = quicker.generateRandomId();
            const code = quicker.generateOtp(6);

            // * Create user
            const payload: IUser = {
                name,
                email,
                password: encryptedPassword,
                phoneNo: {
                    countryCode,
                    isoCode,
                    internationalNumber
                },
                accountConfirmation: {
                    status: false,
                    token,
                    code,
                    timestamp: null
                },
                passwordReset: {
                    token: null,
                    expiry: null,
                    lastResetAt: null
                },
                lastLoginAt: null,
                role: EUserRole.USER,
                timezone: timezone[0].name,
                consent
            };
            const newUser = await databaseService.registerUser(payload);

            // * Send E-mail
            const confirmationUrl = `${config.FRONTEND_URL}/confirmation/${token}?code=${code}`;
            const to = [email];
            const subject = 'Confirm Your Account';
            const text = `Hey ${name}, Please confirm your account by clicking on the link given below:\n\n${confirmationUrl}`;

            emailService.sendEmail(to, subject, text).catch((err) => {
                logger.error('EMAIL_SERVICE', {
                    meta: err
                });
            });
            httpResponse(req, res, 201, responseMessage.SUCCESS, { _id: newUser._id });
        } catch (err) {
            httpError(next, err, req, 500);
        }
    },

    confirmation: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { params, query } = req as IConfirmRequest;

            // TODO:
            const { token } = params;
            const { code } = query;

            // * Fetch user by token
            const user = await databaseService.findUserByConfirmationTokenAndCode(token, code);
            if (!user) {
                return httpError(next, new Error(responseMessage.INVALID_ACCOUNT_CONFIRMATION_OR_CODE), req, 400);
            }

            // * Check if account already confirmed
            if (user.accountConfirmation.status) {
                return httpError(next, new Error(responseMessage.ACCOUNT_ALREADY_CONFIRMED), req, 400);
            }

            // * Account confirm
            user.accountConfirmation.status = true;
            user.accountConfirmation.timestamp = dayjs().utc().toDate();
            await user.save();

            // *Account confirmation email
            const to = [user.email];
            const subject = 'Account confirmed';
            const text = `Your account has been confirmed`;

            emailService.sendEmail(to, subject, text).catch((err) => {
                logger.error('EMAIL_SERVICE', {
                    meta: err
                });
            });
            httpResponse(req, res, 200, responseMessage.SUCCESS);
        } catch (err) {
            httpError(next, err, req, 500);
        }
    },
    login: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { body } = req as ILoginRequest;
            // TODO:
            // * Validate and parse body
            const { error, value } = validateJoiSchema<ILoginRequestBody>(validateLoginBody, body);

            if (error) {
                return httpError(next, error, req, 422);
            }
            const { email, password } = value;
            // * Find user
            const user = await databaseService.findUserByEmail(email, '+password');

            if (!user) {
                return httpError(next, new Error(responseMessage.NOT_FOUND('user')), req, 404);
            }
            // * Validate password
            const isValidPassword = await quicker.comparePassword(password, user.password);

            if (!isValidPassword) {
                return httpError(next, new Error(responseMessage.INVALID_EMAIL_OR_PASSWORD), req, 400);
            }
            // * Access token and refresh token generate

            const accessToken = quicker.generateToken(
                {
                    userId: user.id
                },
                config.ACCESS_TOKEN.SECRET as string,
                config.ACCESS_TOKEN.EXPIRY
            );

            const refreshToken = quicker.generateToken(
                {
                    userId: user.id
                },
                config.REFRESH_TOKEN.SECRET as string,
                config.REFRESH_TOKEN.EXPIRY
            );

            // * Last login information
            user.lastLoginAt = dayjs().utc().toDate();
            await user.save();

            // * Refresh token store
            const refreshTokenPayload: IRefreshToken = {
                token: refreshToken
            };
            await databaseService.createRefreshToken(refreshTokenPayload);

            // * Cookie send
            const DOMAIN = quicker.getDomainFromUrl(config.SERVER_URL as string);

            res.cookie('accessToken', accessToken, {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.ACCESS_TOKEN.EXPIRY,
                httpOnly: true,
                secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT)
            }).cookie('refreshToken', refreshToken, {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.REFRESH_TOKEN.EXPIRY,
                httpOnly: true,
                secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT)
            });

            return httpResponse(req, res, 200, responseMessage.SUCCESS, { accessToken, refreshToken });
        } catch (err) {
            httpError(next, err, req, 500);
        }
    },
    selfIdentification: (req: Request, res: Response, next: NextFunction) => {
        try {
            const { authenticatedUser } = req as ISelfIdentificationRequest;
            httpResponse(req, res, 200, responseMessage.SUCCESS, authenticatedUser);
        } catch (err) {
            httpError(next, err, req, 500);
        }
    },
    logout: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { cookies } = req;
            const { refreshToken } = cookies as {
                refreshToken: string | undefined;
            };
            if (refreshToken) {
                // * db-> delete the refresh token
                await databaseService.deleteRefreshToken(refreshToken);
            }
            const DOMAIN = quicker.getDomainFromUrl(config.SERVER_URL as string);
            // * clear cookies
            res.clearCookie('accessToken', {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.ACCESS_TOKEN.EXPIRY,
                httpOnly: true,
                secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT)
            });
            res.clearCookie('refreshToken', {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 1000 * config.ACCESS_TOKEN.EXPIRY,
                httpOnly: true,
                secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT)
            });
            httpResponse(req, res, 200, responseMessage.SUCCESS);
        } catch (err) {
            httpError(next, err, req, 500);
        }
    },
    refreshToken: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { cookies } = req;
            const { refreshToken, accessToken } = cookies as {
                refreshToken: string | undefined;
                accessToken: string | undefined;
            };
            if (accessToken) {
                return httpResponse(req, res, 200, responseMessage.SUCCESS, { accessToken });
            }

            if (refreshToken) {
                // * Fetch token from database
                const refToken = await databaseService.getRefreshToken(refreshToken);
                if (refToken) {
                    const DOMAIN = quicker.getDomainFromUrl(config.SERVER_URL as string);

                    const { userId } = quicker.verifyToken(refreshToken, config.REFRESH_TOKEN.SECRET as string) as IDecryptedJwt;
                    // * Access token
                    const accessToken = quicker.generateToken(
                        {
                            userId: userId
                        },
                        config.ACCESS_TOKEN.SECRET as string,
                        config.ACCESS_TOKEN.EXPIRY
                    );
                    //* Generate new access token
                    res.cookie('accessToken', accessToken, {
                        path: '/api/v1',
                        domain: DOMAIN,
                        sameSite: 'strict',
                        maxAge: 1000 * config.ACCESS_TOKEN.EXPIRY,
                        httpOnly: true,
                        secure: !(config.ENV === EApplicationEnvironment.DEVELOPMENT)
                    });
                    return httpResponse(req, res, 200, responseMessage.SUCCESS, { accessToken });
                }
            }
            httpError(next, new Error(responseMessage.UNAUTHORIZED), req, 401);
        } catch (err) {
            httpError(next, err, req, 500);
        }
    }
};
