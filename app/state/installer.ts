import { canInstallUpdate, downloadUpdate, installUpdate } from "@tarve/core";
import { setInstaller } from "./updates";

/** Desktop only: lets the updater replace this executable. Android installs through the system. */
setInstaller({ canInstall: canInstallUpdate, download: downloadUpdate, install: installUpdate });
