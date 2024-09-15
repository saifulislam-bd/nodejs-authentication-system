import mongoose from 'mongoose'
import config from '../config/config'
import userModel from '../model/userModel'
import { IUser } from '../types/userType'

export default {
    connect: async () => {
        try {
            await mongoose.connect(config.DATABASE_URL as string)
            return mongoose.connection
        } catch (err) {
            throw err
        }
    },
    findUserByEmail: (email: string)=>{
        return userModel.findOne({email})
    },
    registerUser:(payload:IUser)=>{
        return userModel.create(payload)
    }
}

