import { JwtPayload } from 'jsonwebtoken';
import { EUserRole } from '../constant/userConstant';

export interface IRegisterRequestBody {
    name: string;
    email: string;
    phoneNo: string;
    password: string;
    consent: boolean;
}
export interface ILoginRequestBody {
    email: string;
    password: string;
}

export interface IUser {
    name: string;
    email: string;
    phoneNo: {
        isoCode: string;
        countryCode: string;
        internationalNumber: string;
    };
    timezone: string;
    password: string;
    role: EUserRole;
    accountConfirmation: {
        status: boolean;
        token: string;
        code: string;
        timestamp: Date | null;
    };
    passwordReset: {
        token: string | null;
        expiry: number | null;
        lastResetAt: Date | null;
    };
    lastLoginAt: Date | null;
    consent: boolean;
}

export interface IUserWithId extends IUser {
    _id: string;
}

export interface IRefreshToken {
    token: string;
}

export interface IDecryptedJwt extends JwtPayload {
    userId: string;
}

export interface IForgotPasswordRequestBody {
    email: string;
}

export interface IResetPasswordRequestBody {
    newPassword: string;
}

export interface IChangePasswordRequestBody {
    oldPassword: string;
    newPassword: string;
    confirmNewPassword: string;
}
