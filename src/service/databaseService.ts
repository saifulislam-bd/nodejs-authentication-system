import mongoose from 'mongoose'
import config from '../config/config'
import userModel from '../model/userModel'
import { IRefreshToken, IUser } from '../types/userType'
import refreshTokenModel from '../model/refreshTokenModel'

export default {
    connect: async () => {
        try {
            await mongoose.connect(config.DATABASE_URL as string)
            return mongoose.connection
        } catch (err) {
            throw err
        }
    },
    findUserByEmail: (email: string, select:string='')=>{
        return userModel.findOne({email}).select(select)
    },
    registerUser:(payload:IUser)=>{
        return userModel.create(payload)
    },
    findUserById:(id: string)=>{
        return userModel.findById(id)
    },
    findUserByConfirmationTokenAndCode: (token: string, code: string)=> {
        return userModel.findOne({
            'accountConfirmation.token': token,
            'accountConfirmation.code': code
        })
    },
    createRefreshToken:(payload:IRefreshToken)=>{
        return refreshTokenModel.create(payload)
}
}
