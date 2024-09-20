import mongoose from 'mongoose';
import { IRefreshToken } from '../types/userType';

const refreshTokenSchema = new mongoose.Schema<IRefreshToken>({
  token: {
    type: String,
    required: true
  } 
}, {timestamps: true})

export default mongoose.model<IRefreshToken>('refresh-token', refreshTokenSchema)