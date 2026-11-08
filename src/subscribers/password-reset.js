// Plain CommonJS: Render runs `npx medusa start` without `medusa build`, so
// TypeScript/ESM files in src/ fail to load ("Cannot use import statement").
const { createHmac } = require("node:crypto")

/**
 * Stovima: Medusa makes the password reset token but sends no email. Hand the
 * token to Stovima, which emails the customer a reset link for their store.
 *
 * Env: STOVIMA_PASSWORD_RESET_URL (https://stovima.com/api/webhooks/medusa-password-reset)
 *      MEDUSA_WEBHOOK_SECRET (same value as on Stovima)
 */
async function passwordResetHandler({ event: { data } }) {
  const url = process.env.STOVIMA_PASSWORD_RESET_URL
  const secret = process.env.MEDUSA_WEBHOOK_SECRET
  if (!url || !secret) {
    console.warn("[password-reset] STOVIMA_PASSWORD_RESET_URL or MEDUSA_WEBHOOK_SECRET not set")
    return
  }
  const body = JSON.stringify({
    email: data.entity_id,
    token: data.token,
    actor_type: data.actor_type,
  })
  const signature = createHmac("sha256", secret).update(body).digest("hex")
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-medusa-signature": signature },
      body,
    })
    if (!res.ok) console.warn(`[password-reset] Stovima answered ${res.status}`)
  } catch (err) {
    console.warn("[password-reset] could not reach Stovima:", err.message)
  }
}

module.exports = passwordResetHandler
module.exports.default = passwordResetHandler
module.exports.config = { event: "auth.password_reset" }
