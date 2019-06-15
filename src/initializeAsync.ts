import { loadScriptAsync } from "@alumis/utils/src/loadScriptAsync";

let hasInitialized = false;

export async function initializeAsync() {

    if (!hasInitialized) {

        if (IS_DEV) {

            await loadScriptAsync("openpgp.js");
            await openpgp.initWorker({ path: "openpgp.worker.js" });
        }

        else {

            await loadScriptAsync("openpgp.min.js");
            await openpgp.initWorker({ path: "openpgp.worker.min.js" });
        }

        hasInitialized = true;
    }
}