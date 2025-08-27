/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl

      // SSRF FIX START: Validate the destination hostname
      // Define a list of allowed hostnames for image URLs
      const ALLOWED_IMAGE_HOSTNAMES = [
        'imgur.com',
        'i.imgur.com',
        'images.unsplash.com',
        'cdn.pixabay.com'
        // Add more trusted hostnames as required
      ]
      let allowed = false
      try {
        const parsedUrl = new URL(url)
        allowed = ALLOWED_IMAGE_HOSTNAMES.includes(parsedUrl.hostname)
      } catch (_err) {
        allowed = false
      }
      // SSRF FIX END

      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!allowed) {
            throw new Error('imageUrl points to a non-allowed domain')
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
            // FALLBACK: Save the image URL directly only if it's a valid HTTP/HTTPS URL
            let validImageUrl = false
            try {
              const parsedUrl = new URL(url)
              validImageUrl = (parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:')
            } catch(_err) {
              validImageUrl = false
            }
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: validImageUrl ? url : null })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly (valid: ${validImageUrl})`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
