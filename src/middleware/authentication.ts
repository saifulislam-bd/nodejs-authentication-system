import { NextFunction, Request, Response } from 'express';
import { IUser } from '../types/userType';
import quicker from '../util/quicker';
import config from '../config/config';
import databaseService from '../service/databaseService';
import httpError from '../util/httpError';
import responseMessage from '../constant/responseMessage';
import { IDecryptedJwt } from '../types/userType';

interface IAuthenticatedRequest extends Request {
    authenticatedUser: IUser;
}

export default async (request: Request, _res: Response, next: NextFunction) => {
    try {
        const req = request as IAuthenticatedRequest;
        const { cookies } = req;
        const { accessToken } = cookies as {
            accessToken: string | undefined;
        };

        if (accessToken) {
            // Verify token
            const { userId } = quicker.verifyToken(accessToken, config.ACCESS_TOKEN.SECRET as string) as IDecryptedJwt;

            // Find user by id
            const user = await databaseService.findUserById(userId);
            if (user) {
                req.authenticatedUser = user;
                return next();
            }
        }
        httpError(next, new Error(responseMessage.UNAUTHORIZED), req, 401);
    } catch (error) {
        httpError(next, error, request, 500);
    }
};
