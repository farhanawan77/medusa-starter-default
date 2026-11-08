import { createHmac } from "node:crypto"
import type { SubscriberArgs, SubscriberConfig } from "@medusajs/framework"

/**
 * Stovima: Medusa makes the password reset token but sends no email. Hand the
 * token to Stovima, which emails the customer a reset link for their store.
 *
 * Env: STOVIMA_PASSWORD_RESET_URL (https://stovima.com/api/webhooks/medusa-password-reset)
 *      MEDUSA_WEBHOOK_SECRET (same value as on Stovima)
 */
export default async function passwordResetHandler({
  event: { data },
}: SubscriberArgs<{ entity_id: string; token: string; actor_type: string }>) {
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
    console.warn("[password-reset] could not reach Stovima:", (err as Error).message)
  }
}

export const config: SubscriberConfig = {
  event: "auth.password_reset",
}
