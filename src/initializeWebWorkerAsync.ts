import openpgp from "openpgp";

export async function initializeWebWorkerAsync() {

    if (IS_DEV)
        return openpgp.initWorker({ path: "openpgp.worker.js" });

    return openpgp.initWorker({ path: "openpgp.worker.min.js" });
}