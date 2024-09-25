import joi from 'joi';
import {
    IChangePasswordRequestBody,
    IForgotPasswordRequestBody,
    ILoginRequestBody,
    IRegisterRequestBody,
    IResetPasswordRequestBody
} from '../types/userType';

export const validateRegisterBody = joi.object<IRegisterRequestBody, true>({
    name: joi.string().min(2).max(72).trim().required(),
    email: joi.string().email().required(),
    phoneNo: joi.string().min(4).max(20).required(),
    password: joi.string().min(8).max(24).trim().required(),
    consent: joi.boolean().valid(true).required()
});

export const validateLoginBody = joi.object<ILoginRequestBody, true>({
    email: joi.string().email().required(),
    password: joi.string().min(8).max(24).trim().required()
});

export const validateForgotPasswordBody = joi.object<IForgotPasswordRequestBody, true>({
    email: joi.string().email().required()
});

export const validateResetPasswordBody = joi.object<IResetPasswordRequestBody, true>({
    newPassword: joi.string().min(8).max(24).trim().required()
});

export const validateChangePasswordBody = joi.object<IChangePasswordRequestBody, true>({
    oldPassword: joi.string().min(8).max(24).trim().required(),
    newPassword: joi.string().min(8).max(24).trim().required(),
    confirmNewPassword: joi.string().min(8).max(24).trim().valid(joi.ref('newPassword')).required()
});

export const validateJoiSchema = <T>(schema: joi.Schema, value: unknown) => {
    const result = schema.validate(value);

    return {
        value: result.value as T,
        error: result.error
    };
};
