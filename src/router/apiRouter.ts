import { Router } from 'express'
import apiController from '../controller/apiController'

const router = Router()

router.route('/self').get(apiController.self)
router.route('/health').get(apiController.health)
// eslint-disable-next-line @typescript-eslint/no-misused-promises
router.route('/register').post(apiController.register)

export default router
