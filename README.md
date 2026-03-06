# OpenVPN Install Script

A hardened OpenVPN installer and management script with support for:

* Standard certificate-based clients
* Username/password + certificate clients
* Per-client `.ovpn` export
* Client revoke / export / list
* Optional API webhook integration
* Per-client device limit enforcement
* Active users and bandwidth reporting
* Security hardening helpers
* Backup and restore

Repository: `https://github.com/betaDtech/openvpn-install`

---

## Features

### Core VPN

* Install OpenVPN server on supported Linux distributions
* Auto-detect public IP or use a DNS hostname
* UDP or TCP mode
* IPv4 support with optional IPv6 handling
* EasyRSA-based PKI generation
* Embedded client profiles (`.ovpn`)

### Client Authentication Modes

This script supports **two client modes**:

1. **Cert only**

   * Client authenticates using its own certificate/key
   * Connects to the main OpenVPN server port

2. **Username/Password + Cert**

   * Client must provide:

     * its own client certificate
     * its own private key
     * a Linux username/password created automatically by the script
   * Username must match certificate CN
   * Connects to a dedicated auth instance on port `8443` by default

### Management

* Add client
* Export existing client config
* List clients
* Revoke client
* Remove OpenVPN بالكامل

### Security / Monitoring

* Optional `fail2ban` for SSH
* Optional `fail2ban` for OpenVPN auth instance
* SSH hardening helper
* Active VPN sessions view
* Bandwidth usage report

### Automation / API

* Webhook support for connect / disconnect / rejected events
* Device limit enforcement per client
* Backup / restore support

---

## Supported Operating Systems

* Ubuntu 20.04+
* Debian 10+
* AlmaLinux 8+
* Rocky Linux 8+
* CentOS 8+
* Fedora
* openSUSE
* Amazon Linux 2

### Not Supported

* Amazon Linux 2023
* Old kernels (including OpenVZ 6 style environments)
* Systems without `/dev/net/tun`
* CentOS systems using active `nftables` in unsupported configurations

---

## Authentication Modes Explained

### 1) Cert only

Best when you want the classic OpenVPN model.

**How it works:**

* The script generates a unique certificate and key for each client.
* The exported `.ovpn` file contains everything needed.
* The client connects to the main OpenVPN port (default `1194`).

**Use case:**

* Personal devices
* Managed devices
* Environments where certificate distribution is enough

### 2) Username/Password + Cert

Best when you want stronger control and the ability to tie VPN auth to a local Linux user.

**How it works:**

* The script creates a unique client certificate.
* The script also creates a Linux user with a password.
* OpenVPN validates both:

  * certificate
  * PAM username/password
* The username must match the certificate common name.

**Use case:**

* Per-user access control
* Easier operational control over account lockout
* Stronger identity binding

**Important:**

* Every cert+pass client gets its **own certificate**.
* Every cert+pass client also gets its **own Linux user/password**.
* The exported `.ovpn` profile includes the certificate and key, but the user still has to enter username/password when connecting unless their client app securely stores credentials.

---

## How the Script Works

When OpenVPN is **not installed**, running the script starts installation mode.

When OpenVPN is **already installed**, running the script shows a menu with these options:

1. Add a new client
2. Export config for an existing client
3. List existing clients
4. Revoke an existing client
5. Show active VPN users
6. Bandwidth report
7. API webhook setup
8. Security setup
9. Backup & restore
10. Remove OpenVPN
11. Exit

---

## Requirements

* Root access
* Bash shell
* TUN device enabled
* Internet access during installation
* `systemd`

---

## Installation

### 1) Download the script

```bash
wget https://raw.githubusercontent.com/betaDtech/openvpn-install/master/install.sh -O install.sh
chmod +x install.sh
```

Or:

```bash
curl -fsSL https://raw.githubusercontent.com/betaDtech/openvpn-install/master/install.sh -o install.sh
chmod +x install.sh
```

### 2) Run it

```bash
sudo bash install.sh
```

The script will ask:

* whether clients should use DNS name or IP
* protocol (UDP/TCP)
* port
* DNS provider
* first client name

After setup finishes, the first client profile will be exported as:

```bash
/home/USER/client.ovpn
```

or under root’s home directory if no sudo user is detected.

---

## Automatic Installation

You can also install with CLI flags.

### Example

```bash
sudo bash install.sh \
  --auto \
  --listenaddr 10.0.0.10 \
  --serveraddr vpn.example.com \
  --proto UDP \
  --port 1194 \
  --clientname client \
  --dns1 1.1.1.1 \
  --dns2 1.0.0.1
```

### Available install flags

```bash
--auto
--listenaddr [IPv4 address]
--serveraddr [DNS name or IP]
--proto [TCP or UDP]
--port [1-65535]
--clientname [client name]
--dns1 [DNS server IP]
--dns2 [DNS server IP]
```

---

## Command-Line Usage

### Show help

```bash
bash install.sh --help
```

### Add client directly

```bash
sudo bash install.sh --addclient alice
```

The script will then ask which auth mode to use:

* `1` = Cert only
* `2` = Username/Password + Cert

If you choose cert+pass:

* an auth instance is configured automatically if missing
* you will be prompted for the VPN password
* a Linux user named `alice` is created
* a unique certificate/key pair is generated for `alice`
* `alice.ovpn` is exported

### Export existing client

```bash
sudo bash install.sh --exportclient alice
```

### List clients

```bash
sudo bash install.sh --listclients
```

### Revoke client

```bash
sudo bash install.sh --revokeclient alice
```

### Remove OpenVPN

```bash
sudo bash install.sh --uninstall
```

### Skip confirmation prompts

```bash
sudo bash install.sh --revokeclient alice --yes
sudo bash install.sh --uninstall --yes
```

---

## Interactive Menu Usage

After installation:

```bash
sudo bash install.sh
```

Then choose from the menu.

### 1) Add a new client

You will be asked for:

* client name
* authentication mode
* password if using cert+pass

Result:

* client certificate generated
* `.ovpn` exported
* optional Linux user created for cert+pass mode

### 2) Export config for an existing client

Rebuilds the `.ovpn` profile from the stored cert/key/template.

### 3) List existing clients

Shows all valid client certificates from EasyRSA index.

### 4) Revoke an existing client

* revokes certificate
* regenerates CRL
* removes exported config if found
* if client used cert+pass mode, the Linux user is locked

### 5) Show active VPN users

Displays current connected users from status files for:

* main server
* auth server (if enabled)

### 6) Bandwidth report

Shows total RX/TX per client based on OpenVPN status data and a persistent CSV log.

### 7) API webhook setup

Lets you:

* configure API endpoint
* test webhook
* show current config
* manage multi-device limit

### 8) Security setup

Lets you:

* install and enable fail2ban for SSH
* install and enable fail2ban for OpenVPN auth
* harden SSH config

### 9) Backup & restore

Lets you:

* create a backup archive
* list backups
* restore a backup
* delete older backups

### 10) Remove OpenVPN

Removes installed OpenVPN components and related configuration.

---

## Generated Files and Paths

### Main OpenVPN config

```bash
/etc/openvpn/server/server.conf
```

### Auth instance config

```bash
/etc/openvpn/server/auth.conf
```

### Client templates

```bash
/etc/openvpn/server/client-common.txt
/etc/openvpn/server/client-common-auth.txt
```

### Client mode metadata

```bash
/etc/openvpn/server/clients-meta/
```

Each client gets a mode file such as:

```bash
/etc/openvpn/server/clients-meta/alice.mode
```

Contents:

* `cert`
* `certpass`

### EasyRSA PKI

```bash
/etc/openvpn/server/easy-rsa/
```

### Hook files

```bash
/etc/openvpn/server/hooks/
```

### API config

```bash
/etc/openvpn/server/hooks/api.conf
```

### Device limit config

```bash
/etc/openvpn/server/hooks/max_devices
```

### Hook script

```bash
/etc/openvpn/server/hooks/client-event.sh
```

### Bandwidth log

```bash
/etc/openvpn/server/bandwidth.csv
```

### Backups

```bash
/etc/openvpn/backups/
```

---

## Username/Password + Cert Flow

When you add a client in **certpass** mode, this happens:

1. The script ensures the auth OpenVPN instance exists.
2. The script creates PAM config if needed.
3. The PAM auth plugin is detected.
4. A dedicated OpenVPN instance is created on port `8443`.
5. A helper script validates that username == certificate CN.
6. You are prompted for a hidden password.
7. A Linux user is created with that password and `nologin` shell.
8. A unique certificate is generated for the same client name.
9. The `.ovpn` file is exported using the auth template.

### Result

Example for client `ahmed`:

* Linux user: `ahmed`
* Certificate CN: `ahmed`
* File: `ahmed.ovpn`
* Connection port: `8443`

---

## API Webhook Setup

The script can send webhook events on:

* client connect
* client disconnect
* client rejected (for device limit enforcement)
* manual webhook test

### Menu path

```text
API webhook setup -> Configure API endpoint
```

### Example config prompt

* API URL: `https://example.com/api/vpn`
* API Secret: bearer token or blank

### Stored config

```bash
/etc/openvpn/server/hooks/api.conf
```

Example:

```bash
API_URL="https://example.com/api/vpn"
API_SECRET="your_token_here"
```

### Example JSON payload

```json
{
  "event": "connect",
  "client": "alice",
  "real_ip": "1.2.3.4",
  "real_port": 12345,
  "vpn_ip": "172.16.255.10",
  "bytes_received": 1234,
  "bytes_sent": 5678,
  "timestamp": "2026-03-06T19:00:00Z"
}
```

### Auth header behavior

* If `API_SECRET` is set:

  * `Authorization: Bearer <token>`
* Otherwise:

  * `X-VPN-Hook: 1`

---

## Multi-Device Limit

The script can limit how many simultaneous devices a client can use.

### Menu path

```text
API webhook setup -> Multi-device limit setup
```

### Options

* 1 device per client
* custom number
* show current setting

### How it works

The hook checks active sessions across:

* main server status file
* auth server status file

If a client exceeds the configured limit, the new connection is rejected.

### Default limit file

```bash
/etc/openvpn/server/hooks/max_devices
```

Example:

```bash
1
```

---

## Active Users Report

Menu option:

```text
Show active VPN users
```

This reads status files such as:

```bash
/etc/openvpn/server/openvpn-status.log
/etc/openvpn/server/openvpn-status-auth.log
```

It displays:

* client name
* real IP:port
* virtual IP
* download
* upload
* connection start time

---

## Bandwidth Report

Menu option:

```text
Bandwidth report
```

This uses:

* current OpenVPN status files
* persistent CSV log at `/etc/openvpn/server/bandwidth.csv`

The report shows per-client totals for:

* RX/download
* TX/upload
* last seen

---

## Security Setup

### fail2ban for SSH

Menu:

```text
Security setup -> fail2ban — SSH protection
```

Creates SSH jail with:

* `maxretry = 5`
* `bantime = 3600`
* `findtime = 600`

### fail2ban for OpenVPN auth

Menu:

```text
Security setup -> fail2ban — OpenVPN auth protection
```

Works only when the auth instance exists.

### SSH hardening

Menu:

```text
Security setup -> Harden SSH configuration
```

The script updates `sshd_config` and backs it up first.

Changes include:

* `PermitRootLogin no`
* `MaxAuthTries 4`
* `PermitEmptyPasswords no`
* `X11Forwarding no`
* `LoginGraceTime 30`
* `ClientAliveInterval 300`
* `ClientAliveCountMax 2`

---

## Backup and Restore

### Create backup

Menu:

```text
Backup & restore -> Create backup now
```

Creates a tarball under:

```bash
/etc/openvpn/backups/
```

Backup includes things like:

* PKI files
* OpenVPN configs
* client metadata
* hooks
* bandwidth log
* PAM file if present
* verify-cn helper if present

### Restore backup

Menu:

```text
Backup & restore -> Restore from backup
```

This will overwrite current OpenVPN config. Use it carefully.

### List backups

Menu:

```text
Backup & restore -> List backups
```

### Delete backups

Menu:

```text
Backup & restore -> Delete old backups
```

---

## Service Names

Depending on distro, the script uses:

### Most distros

```bash
openvpn-server@server.service
openvpn-server@auth.service
```

### openSUSE

```bash
openvpn@server.service
openvpn@auth.service
```

---

## Common Examples

### Install with interactive setup

```bash
sudo bash install.sh
```

### Add certificate-only client

```bash
sudo bash install.sh --addclient iphone
```

Then select:

```text
1) Cert only
```

### Add username/password + cert client

```bash
sudo bash install.sh --addclient employee01
```

Then select:

```text
2) Username/Password + Cert
```

You will then enter a password for `employee01`.

### Export client profile again

```bash
sudo bash install.sh --exportclient employee01
```

### Revoke client

```bash
sudo bash install.sh --revokeclient employee01
```

---

## How Client Files Are Exported

The generated `.ovpn` file embeds:

* client config template
* CA certificate
* client certificate
* client private key
* tls-crypt key

For cert+pass mode, the file also includes:

```text
auth-user-pass
auth-nocache
```

That means the VPN app will prompt for username/password unless stored by the client app.

---

## Important Operational Notes

### 1) Linux users for cert+pass mode

The script creates local Linux accounts for cert+pass clients.

That means:

* do not reuse system usernames
* do not try to create VPN clients named `root`
* avoid client names that conflict with existing users

### 2) Client names become certificate CNs

The client name is sanitized and used as the certificate common name.

Allowed characters effectively become:

* letters
* numbers
* `_`
* `-`

Other characters are replaced with `_`.

### 3) Revoking certpass clients

Revocation does **not** fully delete the Linux user. It locks the account.

That is intentional for safer rollback and auditability.

### 4) Webhook hook must exist

API-only config expects the hook script to exist. The device-limit setup creates and maintains the main hook.

### 5) Auth instance uses separate port

Cert+pass clients connect to port `8443` by default, not the main OpenVPN port.

---

## Troubleshooting

### TUN device missing

Error:

```text
The system does not have the TUN device available.
```

Fix:

* enable TUN in your VPS panel
* ensure `/dev/net/tun` exists

### Script run with `sh`

Error:

```text
This installer needs to be run with "bash", not "sh".
```

Fix:

```bash
sudo bash install.sh
```

### Unsupported OS version

Use a supported distro/version from the compatibility list.

### PAM plugin not found

If cert+pass setup fails with PAM plugin error, ensure your OpenVPN package includes the PAM plugin. On Debian/Ubuntu, the script installs OpenVPN and PAM dependencies automatically.

### Client cannot connect in cert+pass mode

Check:

* auth instance is running
* client is using the exported certpass `.ovpn`
* username equals certificate CN
* correct password is being used
* port `8443` is open
* fail2ban is not banning the client IP

### Check service status

```bash
systemctl status openvpn-server@server.service
systemctl status openvpn-server@auth.service
```

On openSUSE:

```bash
systemctl status openvpn@server.service
systemctl status openvpn@auth.service
```

### View logs

```bash
journalctl -u openvpn-server@server.service -e
journalctl -u openvpn-server@auth.service -e
journalctl -u fail2ban -e
```

---

## Recommended Setup Strategy

For most deployments:

1. Use `UDP` unless you have a specific reason to use TCP.
2. Use a DNS hostname instead of raw IP if possible.
3. Use **cert only** for personal/admin devices.
4. Use **username/password + cert** for end users or employees.
5. Enable **1 device per client** if account sharing is a problem.
6. Enable **fail2ban** and harden SSH.
7. Create regular backups before major changes.

---

## Uninstall

### Interactive

```bash
sudo bash install.sh
```

Then choose:

```text
10) Remove OpenVPN
```

### Direct

```bash
sudo bash install.sh --uninstall
```

---

## License

Released under the MIT License.

See `LICENSE.txt` or the MIT license website for details.

---

## Credits

Based on work by:

* Nyr and contributors
* hwdsl2/openvpn-install

Customized and extended by:

* betaDtech

---

## Example GitHub README Quick Start

```bash
git clone https://github.com/betaDtech/openvpn-install.git
cd openvpn-install
chmod +x install.sh
sudo bash install.sh
```

Then:

* complete installation
* take the exported `.ovpn`
* import it into OpenVPN Connect or another compatible client
* for cert+pass clients, log in with the same client name and the password you set during creation
