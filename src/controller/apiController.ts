import { NextFunction, Request, Response } from 'express'
import httpResponse from '../util/httpResponse'
import responseMessage from '../constant/responseMessage'
import httpError from '../util/httpError'
import quicker from '../util/quicker'
import { IRegisterRequestBody, IUser } from '../types/userType'
import { validateJoiSchema, validateRegisterBody } from '../service/validationService'
import databaseService from '../service/databaseService'
import { EUserRole } from '../constant/userConstant'
import config from '../config/config'
import emailService from '../service/emailService'
import logger from '../util/logger'

interface IRegisterRequest extends Request {
    body: IRegisterRequestBody
}


export default {
    self: (req: Request, res: Response, next: NextFunction) => {
        try {
            httpResponse(req, res, 200, responseMessage.SUCCESS)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },

    health: (req: Request, res: Response, next: NextFunction) => {
        try {
            const healthData = {
                application: quicker.getApplicationHealth(),
                system: quicker.getSystemHealth(),
                timestamp: Date.now()
            }

            httpResponse(req, res, 200, responseMessage.SUCCESS, healthData)
        } catch (err) {
            httpError(next, err, req, 500)
        }
    },

    register: async(req: Request, res: Response, next: NextFunction) => {
        try {
            const {body} = req as IRegisterRequest;
            
        // TODO: Add Register logic
        // * Body validation
            const {error, value} = validateJoiSchema<IRegisterRequestBody>(validateRegisterBody, body);

            if(error) {
                return httpError(next, error, req, 422)
            }
        // * Phone no parsing and validation
            const {phoneNo,name, consent, email, password} = value;
            const {countryCode, internationalNumber, isoCode} = quicker.parsePhoneNumber('+' + phoneNo);

            if(!countryCode || !isoCode || !internationalNumber) {
                return httpError(next, new Error(responseMessage.INVALID_PHONE_NUMBER), req, 422)
            }  

        // * Timzezone
          const timezone =  quicker.countryTimezone(isoCode);
          if(!timezone || timezone.length === 0) {
            return httpError(next, new Error(responseMessage.INVALID_PHONE_NUMBER), req, 422)
          }
          
         // * Check user existence using email address
            const user = await databaseService.findUserByEmail(email)
            if (user) {
                return httpError(next, new Error(responseMessage.ALREADY_EXIST('user', email)), req, 422)
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
            phoneNo:{
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
            lastLoginAt:  null,
            role: EUserRole.USER,
            timezone: timezone[0].name,
            consent
            }
            const newUser = await databaseService.registerUser(payload);

        // * Send E-mail
            const confirmationUrl = `${config.FRONTEND_URL}/confirmation/${token}?code=${code}`;
            const to = [email];
            const subject = 'Confirm Your Account';
            const text = `Hey ${name}, Please confirm your account by clicking on the link given below:\n\n${confirmationUrl}`;

            emailService.sendEmail(to,subject,text).catch((err)=>{
                logger.error('EMAIL_SERVICE',{
                    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
                    meta: err
                })
            })
            httpResponse(req, res, 201, responseMessage.SUCCESS, {_id:newUser._id})
        } catch (err) {
            httpError(next, err, req, 500)
        }
    }
}
