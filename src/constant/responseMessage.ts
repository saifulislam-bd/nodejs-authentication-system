export default {
    SUCCESS: `The operation has been successful`,
    SOMETHING_WENT_WRONG: `Something went wrong!`,
    NOT_FOUND: (entity: string) => `${entity} not found`,
    TOO_MANY_REQUESTS: `Too many requests! Please try again after some time`,
    INVALID_PHONE_NUMBER: `Invalid phone number!`,
    ALREADY_EXIST: (entity: string, identifier: string) => {
        return `${entity} already exists with '${identifier}' email address`;
    },
    INVALID_ACCOUNT_CONFIRMATION_OR_CODE: `Invalid account confirmation or code`,
    ACCOUNT_ALREADY_CONFIRMED: `Account already confirmed`,
    INVALID_EMAIL_OR_PASSWORD: `Invalid Email or Password`,
    UNAUTHORIZED: `You are not authorized`,
    ACCOUNT_CONFIRMATION_REQUIRED: 'Account confirmation required'
};
