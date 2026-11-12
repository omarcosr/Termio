/**
 * Desktop entry: the app plus the self-updater, whose file APIs the Android runtime does not have.
 * Android builds app/main.tsx directly.
 */
import "./state/installer";
import "./main";
