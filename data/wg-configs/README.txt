Your WireGuard .conf files live here (one file per server; each = one lane
= one dedicated egress IP). PRELOADED: 5 Proton configs from your dummy
accounts (verified: 4-5 tunnels come up with distinct exit IPs).

Where to get more (free, no card):

  Proton VPN    account.protonvpn.com -> Downloads -> WireGuard
                configuration (login = your Proton account email + password;
                the .conf itself needs NO username/password - keys are inside
                the file; ignore the OpenVPN/IKEv2 credentials on that page)

  PrivadoVPN    log in at privadovpn.com -> Dashboard tab -> scroll down ->
                Manual Configuration -> WireGuard -> generate per server
                (available on the FREE plan; 10 GB/mo)

  Windscribe    NOT POSSIBLE on free (verified Aug 2026: WireGuard/OpenVPN
                config generators are Pro/Build-A-Plan only) - do not waste
                time there under the no-upgrade condition

Notes:
  * .conf files with Windows CRLF endings are fine (the parser strips \r)
  * restart after adding files:  ./stop.sh && ./run.sh
  * these files contain private keys - this folder is mounted into the
    container only; keep the zip private
