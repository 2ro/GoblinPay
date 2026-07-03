import { ModuleProvider, Modules } from "@medusajs/framework/utils"

import GoblinPayProviderService from "./service"

// Register GoblinPay as a Medusa v2 payment-module provider. Referenced from
// medusa-config.ts under the payment module's `providers` (see INSTALL.md).
export default ModuleProvider(Modules.PAYMENT, {
  services: [GoblinPayProviderService],
})
