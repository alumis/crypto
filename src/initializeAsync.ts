import { loadScriptAsync } from "@alumis/utils/src/loadScriptAsync";

let hasInitialized = false;

export async function initializeAsync() {

    if (!hasInitialized) {

        await loadScriptAsync(OPENPGP_PATH);
        await openpgp.initWorker({ path: OPENPGP_WORKER_PATH });

        hasInitialized = true;
    }
}