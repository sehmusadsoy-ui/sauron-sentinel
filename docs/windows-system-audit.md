# System Security: optional read-only Windows checks

This panel is part of the local Sauron Sentinel desktop/browser dashboard, subject to the review and release gates on the corresponding PR. It does **not** perform active penetration testing, continuously monitor ports, remove malware, edit Windows settings, start background services, or protect against a compromised local administrator.

## User flow

1. Open Sauron Sentinel on Windows 10/11 from a trusted verified build.
2. Navigate to **Sistem Güvenliği** and click **Sistem ayarlarını denetle**.
3. Review every item marked **İnceleme gerekli** and **Doğrulanamadı**. An **OK** result means only the narrow setting was read and appeared acceptable; it is **not** a guarantee that the computer is uncompromised.
4. If Remote Desktop/SSH/WinRM/remote-support tools are listed, verify that you installed them intentionally. Do not disable a remote-access service if it is needed for your work without checking how you will reconnect.
5. Review Windows Update, Defender, disk encryption and available backups separately. WSL networking, router port forwarding, malware persistence, GitHub account sessions and token exposure are outside this panel's full scope.

Results are shown locally for the current window session only; this panel does not add new SQLite tables, export audit data, install software, download scripts, or request administrative elevation.

## Technical boundaries

- `POST /api/system-exposure` is local-loopback-only, uses the existing dashboard token plus Host/Origin checks, accepts only an empty body, and allows only one simultaneous audit.
- A fixed, packaged PowerShell script contains all checks. No browser-supplied argument is interpolated into executable code. It runs with `-NoProfile`, `-NonInteractive` and a 20-second timeout, with stderr suppressed.
- The response is validated and size-bounded before it reaches the dashboard. Errors are generic and avoid full Windows paths, usernames or account secrets.
- The interface inserts diagnostic strings using DOM `textContent` rather than `innerHTML`.
- The packaged script was derived from `scripts/windows-exposure-readonly.ps1`. CI checks its syntax and a source parity test checks that the underlying read-only checks stay aligned.

## Manual acceptance requirements (not automated in CI)

- [ ] Run the application on a real Windows 11 PC with an ordinary, non-elevated account.
- [ ] Confirm no UAC prompt, setting change, network request, upload or new output file is made by the audit.
- [ ] Test normal readings, restricted account/permission failures and an unavailable PowerShell case.
- [ ] Confirm all result cards render without layout overflow and that a second click during an active check cannot start another audit.
- [ ] Confirm closing the application stops the dashboard and audit cannot run afterwards.
- [ ] Test the packaged Windows executable (not only `python -m`) to verify `windows_exposure.ps1` is bundled and readable.

Do not post unredacted scan output publicly. If there are signs of a real compromise, disconnect the affected host from untrusted networks and obtain a controlled forensic review; this narrow configuration audit cannot establish root cause.
