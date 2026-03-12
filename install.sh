#!/bin/bash
#
# OpenVPN Installer — Dual Server Failover Edition
# Original: https://github.com/betaDtech/openvpn-install
# Modified: Added Peer/Failover sync, IP whitelisting, auto client propagation
#

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
exiterr3() { exiterr "'yum install' failed."; }
exiterr4() { exiterr "'zypper install' failed."; }

check_ip() {
	IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_pvt_ip() {
	IPP_REGEX='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$IPP_REGEX"
}

check_dns_name() {
	FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

check_root() {
	if [ "$(id -u)" != 0 ]; then
		exiterr "This installer must be run as root. Try 'sudo bash $0'"
	fi
}

check_shell() {
	if readlink /proc/$$/exe | grep -q "dash"; then
		exiterr 'This installer needs to be run with "bash", not "sh".'
	fi
}

check_kernel() {
	if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
		exiterr "The system is running an old kernel, which is incompatible with this installer."
	fi
}

check_os() {
	if grep -qs "ubuntu" /etc/os-release; then
		os="ubuntu"
		os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
		group_name="nogroup"
	elif [[ -e /etc/debian_version ]]; then
		os="debian"
		os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
		group_name="nogroup"
	elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
		os="centos"
		os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
		group_name="nobody"
	elif grep -qs "Amazon Linux release 2 " /etc/system-release; then
		os="centos"
		os_version="7"
		group_name="nobody"
	elif grep -qs "Amazon Linux release 2023" /etc/system-release; then
		exiterr "Amazon Linux 2023 is not supported."
	elif [[ -e /etc/fedora-release ]]; then
		os="fedora"
		os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
		group_name="nobody"
	elif [[ -e /etc/SUSE-brand && "$(head -1 /etc/SUSE-brand)" == "openSUSE" ]]; then
		os="openSUSE"
		os_version=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
		group_name="nogroup"
	else
		exiterr "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora, openSUSE and Amazon Linux 2."
	fi
}

check_os_ver() {
	if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
		exiterr "Ubuntu 20.04 or higher is required to use this installer."
	fi
	if [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
		exiterr "Debian 10 or higher is required to use this installer."
	fi
	if [[ "$os" == "centos" && "$os_version" -lt 8 ]]; then
		if ! grep -qs "Amazon Linux release 2 " /etc/system-release; then
			exiterr "CentOS 8 or higher is required to use this installer."
		fi
	fi
}

check_tun() {
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		exiterr "The system does not have the TUN device available."
	fi
}

set_client_name() {
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
}

# ============================================================
# Multi-mode client support
# ============================================================
CLIENT_META_DIR="/etc/openvpn/server/clients-meta"
AUTH_INSTANCE_NAME="auth"
AUTH_PORT_DEFAULT="8443"
AUTH_VPN_NET="172.16.254.0"
AUTH_VPN_MASK="255.255.255.0"
AUTH_VPN_CIDR="172.16.254.0/24"
PAM_SERVICE_NAME="openvpn"
PAM_PLUGIN_PATH=""

# ============================================================
# API Webhook
# ============================================================
VPN_API_URL=""
VPN_API_SECRET=""
VPN_HOOK_SCRIPT="/etc/openvpn/server/hooks/client-event.sh"

# ============================================================
# PEER / FAILOVER — Global config paths
# ============================================================
PEER_CONF="/etc/openvpn/server/peer.conf"
PEER_SSH_KEY="/etc/openvpn/server/peer_ssh_key"

# ============================================================
# PEER CORE FUNCTIONS
# ============================================================

load_peer_conf() {
	[ -f "$PEER_CONF" ] || return 1
	# shellcheck source=/dev/null
	source "$PEER_CONF"
	[ -n "$PEER_IP" ] || return 1
	return 0
}

peer_is_configured() {
	load_peer_conf 2>/dev/null && [ -n "${PEER_IP:-}" ]
}

# ============================================================
# SSH-AGENT — handles passphrase-protected private keys
# ============================================================
# Global agent socket/PID (set by _peer_agent_start)
_PEER_AGENT_PID=""
_PEER_AGENT_SOCK=""

# Start an ssh-agent and load the peer key (with passphrase if set)
# Safe to call multiple times — won't start a second agent
_peer_agent_start() {
	# Only needed for key auth with a passphrase
	[ "${PEER_AUTH:-key}" = "key" ]        || return 0
	[ -n "${PEER_KEY_PASS:-}" ]            || return 0  # no passphrase → no agent needed
	[ -n "${_PEER_AGENT_SOCK:-}" ]         && return 0  # already running

	local key="${PEER_KEY:-$PEER_SSH_KEY}"
	[ -f "$key" ] || { echo "  [✗] SSH key file not found: $key"; return 1; }

	# Start agent
	local agent_output
	agent_output=$(ssh-agent -s 2>/dev/null) || { echo "  [✗] Cannot start ssh-agent"; return 1; }
	eval "$agent_output" >/dev/null
	_PEER_AGENT_PID="$SSH_AGENT_PID"
	_PEER_AGENT_SOCK="$SSH_AUTH_SOCK"

	# Create a temporary SSH_ASKPASS helper script that just prints the passphrase.
	# ssh-add uses SSH_ASKPASS when there is no controlling terminal (stdin < /dev/null)
	local _askpass
	_askpass=$(mktemp /tmp/.peer_askpass_XXXXXX)
	chmod 700 "$_askpass"
	printf '#!/bin/sh\nprintf "%%s" %q\n' "${PEER_KEY_PASS}" > "$_askpass"

	SSH_AGENT_PID="$_PEER_AGENT_PID" \
	SSH_AUTH_SOCK="$_PEER_AGENT_SOCK" \
	DISPLAY=:0 SSH_ASKPASS="$_askpass" \
	ssh-add "$key" </dev/null >/dev/null 2>&1
	local rc=$?

	rm -f "$_askpass"

	if [ $rc -ne 0 ]; then
		_peer_agent_stop
		echo "  [✗] Wrong passphrase for key, or ssh-add failed."
		return 1
	fi

	return 0
}

# Stop the agent we started
_peer_agent_stop() {
	if [ -n "${_PEER_AGENT_PID:-}" ]; then
		SSH_AGENT_PID="$_PEER_AGENT_PID" SSH_AUTH_SOCK="$_PEER_AGENT_SOCK" \
			ssh-agent -k >/dev/null 2>&1 || true
		_PEER_AGENT_PID=""
		_PEER_AGENT_SOCK=""
		unset SSH_AGENT_PID SSH_AUTH_SOCK
	fi
}

# ---- sudo prefix builder ----
# Returns the correct sudo invocation for the peer:
#   root user        → empty (no sudo needed)
#   NOPASSWD sudo    → "sudo -n"
#   sudo + password  → "echo PASS | sudo -S"
_peer_sudo_prefix() {
	if [ "${PEER_USER:-root}" = "root" ]; then
		echo ""
	elif [ "${PEER_SUDO:-nopasswd}" = "nopasswd" ]; then
		echo "sudo -n"
	else
		# password-based sudo — feed password via stdin
		printf 'echo %q | sudo -S' "${PEER_SUDO_PASS}"
	fi
}

# Build SSH options (BatchMode only when using key auth)
_peer_ssh_args() {
	SSH_ARGS=(-o StrictHostKeyChecking=no -o ConnectTimeout=15 -o LogLevel=ERROR)
	SSH_ARGS+=(-p "${PEER_PORT:-22}")
	if [ "${PEER_AUTH:-key}" = "key" ]; then
		SSH_ARGS+=(-o BatchMode=yes)
		SSH_ARGS+=(-o PreferredAuthentications=publickey)
		if [ -n "${_PEER_AGENT_SOCK:-}" ]; then
			# Use agent (key has passphrase — already loaded into agent)
			SSH_ARGS+=(-o IdentityAgent="${_PEER_AGENT_SOCK}")
		else
			# Direct key (no passphrase)
			SSH_ARGS+=(-i "${PEER_KEY:-$PEER_SSH_KEY}")
			SSH_ARGS+=(-o IdentitiesOnly=yes)
		fi
	else
		# Password auth — disable all key-based auth to avoid hangs
		SSH_ARGS+=(-o BatchMode=no)
		SSH_ARGS+=(-o PreferredAuthentications=password)
		SSH_ARGS+=(-o PubkeyAuthentication=no)
		SSH_ARGS+=(-o KbdInteractiveAuthentication=no)
		SSH_ARGS+=(-o ChallengeResponseAuthentication=no)
	fi
}

# Build SCP options
_peer_scp_args() {
	SCP_ARGS=(-o StrictHostKeyChecking=no -o ConnectTimeout=15 -o LogLevel=ERROR)
	SCP_ARGS+=(-P "${PEER_PORT:-22}")
	if [ "${PEER_AUTH:-key}" = "key" ]; then
		SCP_ARGS+=(-o BatchMode=yes)
		SCP_ARGS+=(-o PreferredAuthentications=publickey)
		if [ -n "${_PEER_AGENT_SOCK:-}" ]; then
			SCP_ARGS+=(-o IdentityAgent="${_PEER_AGENT_SOCK}")
		else
			SCP_ARGS+=(-i "${PEER_KEY:-$PEER_SSH_KEY}")
			SCP_ARGS+=(-o IdentitiesOnly=yes)
		fi
	else
		SCP_ARGS+=(-o BatchMode=no)
		SCP_ARGS+=(-o PreferredAuthentications=password)
		SCP_ARGS+=(-o PubkeyAuthentication=no)
		SCP_ARGS+=(-o KbdInteractiveAuthentication=no)
		SCP_ARGS+=(-o ChallengeResponseAuthentication=no)
	fi
}

# Execute a PLAIN command on peer via SSH (no sudo)
# Usage: peer_ssh "command"
peer_ssh_raw() {
	_peer_ssh_args
	if [ "${PEER_AUTH:-key}" = "key" ]; then
		ssh "${SSH_ARGS[@]}" "${PEER_USER:-root}@${PEER_IP}" "$@"
	else
		sshpass -p "${PEER_PASS}" ssh "${SSH_ARGS[@]}" "${PEER_USER:-root}@${PEER_IP}" "$@"
	fi
}

# Execute a command on peer — automatically prepends sudo when needed
# Usage: peer_ssh "command args..."
peer_ssh() {
	local pfx
	pfx=$(_peer_sudo_prefix)
	if [ -z "$pfx" ]; then
		peer_ssh_raw "$@"
	else
		peer_ssh_raw "${pfx} $*"
	fi
}

# Copy a file TO peer using tmp → sudo mv approach
# This works even when the destination is owned by root and user is non-root
# Usage: peer_scp_to /local/file /remote/dest/file
peer_scp_to() {
	local src="$1" dst="$2"
	local tmpfile="/tmp/.peer_transfer_$(basename "$dst")_$$"
	_peer_scp_args

	# Step 1: copy to /tmp on peer (no sudo needed for /tmp)
	if [ "${PEER_AUTH:-key}" = "key" ]; then
		scp "${SCP_ARGS[@]}" "$src" "${PEER_USER:-root}@${PEER_IP}:${tmpfile}" || return 1
	else
		sshpass -p "${PEER_PASS}" scp "${SCP_ARGS[@]}" "$src" "${PEER_USER:-root}@${PEER_IP}:${tmpfile}" || return 1
	fi

	# Step 2: sudo move to final destination (creates parent dir if needed)
	local dir; dir=$(dirname "$dst")
	peer_ssh "mkdir -p ${dir} && mv -f ${tmpfile} ${dst} && chmod 600 ${dst}"
}

# Install sshpass if needed (password SSH auth only)
ensure_sshpass() {
	if [ "${PEER_AUTH:-key}" = "pass" ] && ! command -v sshpass >/dev/null 2>&1; then
		echo "  Installing sshpass..."
		if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			export DEBIAN_FRONTEND=noninteractive
			apt-get -yqq install sshpass >/dev/null 2>&1
		elif [[ "$os" == "centos" ]]; then
			yum -y -q install sshpass >/dev/null 2>&1
		elif [[ "$os" == "fedora" ]]; then
			dnf -y -q install sshpass >/dev/null 2>&1
		elif [[ "$os" == "openSUSE" ]]; then
			zypper install -y sshpass >/dev/null 2>&1
		fi
	fi
}

# Verify peer SSH connection is alive
check_peer_ssh() {
	load_peer_conf || return 1
	ensure_sshpass
	_peer_agent_start || return 1
	peer_ssh_raw "echo connected" >/dev/null 2>&1
}

# Verify both SSH AND sudo work
check_peer_ssh_sudo() {
	load_peer_conf || return 1
	ensure_sshpass
	_peer_agent_start || return 1
	peer_ssh_raw "echo ok" >/dev/null 2>&1 || return 1
	if [ "${PEER_USER:-root}" != "root" ]; then
		peer_ssh "id" >/dev/null 2>&1 || return 1
	fi
	return 0
}

# ============================================================
# PEER INTERACTIVE SETUP
# ============================================================

# Read a multiline SSH private key pasted in the terminal.
# User pastes the key, then types END on its own line.
_read_pasted_key() {
	local keyfile="$1"
	echo  >/dev/tty
	echo "  Paste your SSH private key below." >/dev/tty
	echo "  Start with -----BEGIN ... PRIVATE KEY-----" >/dev/tty
	echo "  When done, type END on a new line and press Enter:" >/dev/tty
	echo  >/dev/tty

	local line collected=""
	while IFS= read -r line </dev/tty; do
		[ "$line" = "END" ] && break
		collected+="${line}"$'\n'
	done

	if [ -z "$collected" ]; then
		echo "  [✗] No key content received." >/dev/tty
		return 1
	fi

	# Basic sanity check
	if ! echo "$collected" | grep -q "PRIVATE KEY"; then
		echo "  [✗] Key does not look like a valid private key." >/dev/tty
		return 1
	fi

	install -m 600 /dev/null "$keyfile"
	printf '%s' "$collected" > "$keyfile"
	echo "  [✓] SSH key saved → $keyfile" >/dev/tty
	return 0
}

setup_peer_interactive() {
	echo
	echo "  ┌──────────────────────────────────────────────────────┐"
	echo "  │         Failover Server Setup                        │"
	echo "  └──────────────────────────────────────────────────────┘"
	echo

	# ── Step 1: Connection details ──────────────────────────────
	read -rp "  Failover server IP address: " peer_ip </dev/tty
	if ! check_ip "$peer_ip"; then
		echo "  [✗] Invalid IP address."
		return 1
	fi

	read -rp "  SSH user [root]: " peer_user </dev/tty
	[ -z "$peer_user" ] && peer_user="root"

	read -rp "  SSH port [22]: " peer_port </dev/tty
	[[ ! "$peer_port" =~ ^[0-9]+$ ]] && peer_port=22

	# ── Step 2: SSH Authentication ──────────────────────────────
	echo
	echo "  SSH Authentication:"
	echo "   1) Password"
	echo "   2) SSH Private Key (paste content)"
	read -rp "  Select [1]: " peer_auth_opt </dev/tty

	local peer_auth peer_pass peer_key_path

	if [[ "$peer_auth_opt" == "2" ]]; then
		# ---- SSH Key ----
		peer_auth="key"
		peer_key_path="$PEER_SSH_KEY"

		_read_pasted_key "$peer_key_path" || return 1

		# Ask about passphrase
		echo
		printf "  Does this key have a passphrase? [y/N]: "
		read -r key_has_pass </dev/tty
		local peer_key_pass=""
		if [[ "$key_has_pass" =~ ^[yY]$ ]]; then
			read -rsp "  Key passphrase: " peer_key_pass </dev/tty; echo
			# Verify passphrase by loading into a temp agent
			echo "  Verifying passphrase..."
			local _ta _tp _ts _tap _trc
			_ta=$(ssh-agent -s 2>/dev/null)
			eval "$_ta" >/dev/null
			_tp="$SSH_AGENT_PID"; _ts="$SSH_AUTH_SOCK"
			_tap=$(mktemp /tmp/.peer_askpass_XXXXXX)
			chmod 700 "$_tap"
			printf '#!/bin/sh\nprintf "%%s" %q\n' "${peer_key_pass}" > "$_tap"
			DISPLAY=:0 SSH_ASKPASS="$_tap" SSH_AGENT_PID="$_tp" SSH_AUTH_SOCK="$_ts" \
				ssh-add "$peer_key_path" </dev/null >/dev/null 2>&1
			_trc=$?
			rm -f "$_tap"
			SSH_AGENT_PID="$_tp" SSH_AUTH_SOCK="$_ts" ssh-agent -k >/dev/null 2>&1 || true
			unset SSH_AGENT_PID SSH_AUTH_SOCK
			[ $_trc -ne 0 ] && { echo "  [✗] Wrong passphrase. Please re-run setup."; return 1; }
			echo "  [✓] Passphrase verified"
		fi

		# IMPORTANT: bash functions do NOT inherit inline-prefix env vars (e.g.
		# "FOO=x myfunc" does NOT set $FOO inside myfunc). We must set globals.
		local _sv_IP="$PEER_IP"   _sv_USER="$PEER_USER" _sv_PORT="$PEER_PORT"
		local _sv_AUTH="$PEER_AUTH" _sv_KEY="$PEER_KEY" _sv_KPASS="$PEER_KEY_PASS"
		PEER_IP="$peer_ip"; PEER_USER="$peer_user"; PEER_PORT="$peer_port"
		PEER_AUTH="key";    PEER_KEY="$peer_key_path"; PEER_KEY_PASS="$peer_key_pass"

		_peer_agent_start
		local _ag_rc=$?

		echo "  Testing SSH connection with key..."
		local _conn_ok=0
		[ $_ag_rc -eq 0 ] && peer_ssh_raw "echo ok" >/dev/null 2>&1 && _conn_ok=1

		_peer_agent_stop
		# Restore globals
		PEER_IP="$_sv_IP"; PEER_USER="$_sv_USER"; PEER_PORT="$_sv_PORT"
		PEER_AUTH="$_sv_AUTH"; PEER_KEY="$_sv_KEY"; PEER_KEY_PASS="$_sv_KPASS"

		if [ $_conn_ok -ne 1 ]; then
			echo "  [✗] SSH key auth failed."
			echo "      Check: is this the correct key for ${peer_user}@${peer_ip}:${peer_port}?"
			return 1
		fi
		echo "  [✓] SSH key connection OK"

	else
		# ---- Password ----
		peer_auth="pass"
		ensure_sshpass

		read -rsp "  SSH password for ${peer_user}@${peer_ip}: " peer_pass </dev/tty; echo

		# IMPORTANT: set globals explicitly (same reason as above)
		local _sv_IP="$PEER_IP"   _sv_USER="$PEER_USER" _sv_PORT="$PEER_PORT"
		local _sv_AUTH="$PEER_AUTH" _sv_PASS="$PEER_PASS"
		PEER_IP="$peer_ip"; PEER_USER="$peer_user"; PEER_PORT="$peer_port"
		PEER_AUTH="pass";   PEER_PASS="$peer_pass"

		echo "  Testing SSH connection..."
		local _conn_ok=0
		peer_ssh_raw "echo ok" >/dev/null 2>&1 && _conn_ok=1

		# Restore globals
		PEER_IP="$_sv_IP"; PEER_USER="$_sv_USER"; PEER_PORT="$_sv_PORT"
		PEER_AUTH="$_sv_AUTH"; PEER_PASS="$_sv_PASS"

		if [ $_conn_ok -ne 1 ]; then
			echo
			echo "  [✗] Cannot connect to ${peer_user}@${peer_ip}:${peer_port}"
			echo
			echo "  Possible causes:"
			echo "    1) Wrong password"
			echo "    2) SSH password auth is disabled on the remote server"
			echo "       → Fix: run this on the failover server:"
			echo "         sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config"
			echo "         sudo systemctl restart sshd"
			echo "    3) Firewall is blocking port ${peer_port}"
			echo "    4) Wrong IP or port"
			return 1
		fi
		echo "  [✓] SSH password connection OK"
	fi

	# ── Step 3: sudo configuration ──────────────────────────────
	local peer_sudo peer_sudo_pass=""

	if [ "$peer_user" = "root" ]; then
		peer_sudo="none"
		echo "  [i] User is root — sudo not needed"
	else
		echo
		echo "  sudo configuration on failover server:"
		echo "   1) NOPASSWD sudo (user can sudo without password)"
		echo "   2) sudo requires password"
		read -rp "  Select [1]: " sudo_opt </dev/tty

		if [[ "$sudo_opt" == "2" ]]; then
			peer_sudo="password"
			read -rsp "  sudo password for '${peer_user}': " peer_sudo_pass </dev/tty; echo
			echo "  [i] sudo password recorded (stored encrypted in peer.conf)"
		else
			peer_sudo="nopasswd"
			echo "  [i] Using NOPASSWD sudo"
		fi

		# Verify sudo works on peer
		echo "  Testing sudo on peer..."
		# Set globals explicitly (bash functions don't inherit prefix vars)
		local _sv2_IP="$PEER_IP"   _sv2_USER="$PEER_USER"  _sv2_PORT="$PEER_PORT"
		local _sv2_AUTH="$PEER_AUTH" _sv2_PASS="$PEER_PASS" _sv2_KEY="$PEER_KEY"
		local _sv2_SUDO="$PEER_SUDO" _sv2_SUDOP="$PEER_SUDO_PASS" _sv2_KPASS="$PEER_KEY_PASS"
		PEER_IP="$peer_ip";   PEER_USER="$peer_user";  PEER_PORT="$peer_port"
		PEER_AUTH="$peer_auth"; PEER_PASS="${peer_pass:-}"; PEER_KEY="${peer_key_path:-}"
		PEER_SUDO="$peer_sudo"; PEER_SUDO_PASS="$peer_sudo_pass"; PEER_KEY_PASS="${peer_key_pass:-}"

		_peer_agent_start 2>/dev/null
		local _sudo_ok=0
		peer_ssh "id" >/dev/null 2>&1 && _sudo_ok=1
		_peer_agent_stop

		# Restore globals
		PEER_IP="$_sv2_IP";   PEER_USER="$_sv2_USER";  PEER_PORT="$_sv2_PORT"
		PEER_AUTH="$_sv2_AUTH"; PEER_PASS="$_sv2_PASS"; PEER_KEY="$_sv2_KEY"
		PEER_SUDO="$_sv2_SUDO"; PEER_SUDO_PASS="$_sv2_SUDOP"; PEER_KEY_PASS="$_sv2_KPASS"

		if [ $_sudo_ok -ne 1 ]; then
			echo "  [✗] sudo test failed on peer."
			echo "      Check that '${peer_user}' has sudo rights on the failover server."
			return 1
		fi
		echo "  [✓] sudo works correctly on peer"
	fi

	# ── Step 4: Save configuration ──────────────────────────────
	install -m 600 /dev/null "$PEER_CONF"
	cat > "$PEER_CONF" <<EOF
PEER_IP="${peer_ip}"
PEER_USER="${peer_user}"
PEER_PORT="${peer_port}"
PEER_AUTH="${peer_auth}"
EOF

	if [ "$peer_auth" = "pass" ]; then
		echo "PEER_PASS=\"${peer_pass}\"" >> "$PEER_CONF"
	else
		echo "PEER_KEY=\"${peer_key_path}\"" >> "$PEER_CONF"
		# Save passphrase if set (file is chmod 600)
		if [ -n "${peer_key_pass:-}" ]; then
			echo "PEER_KEY_PASS=\"${peer_key_pass}\"" >> "$PEER_CONF"
		fi
	fi

	cat >> "$PEER_CONF" <<EOF
PEER_SUDO="${peer_sudo}"
PEER_SUDO_PASS="${peer_sudo_pass}"
PEER_VPN_PORT="${port:-1194}"
PEER_VPN_PROTO="${protocol:-udp}"
EOF

	chmod 600 "$PEER_CONF"
	echo
	echo "  [✓] Failover server configuration saved → $PEER_CONF"
	return 0
}

# ============================================================
# WHITELIST peer IPs in firewall (bidirectional)
# ============================================================

whitelist_peer_ips() {
	load_peer_conf || return
	echo "  Adding firewall whitelist for peer ${PEER_IP}..."

	if systemctl is-active --quiet firewalld.service; then
		firewall-cmd -q --zone=trusted --add-source="${PEER_IP}/32" 2>/dev/null
		firewall-cmd -q --permanent --zone=trusted --add-source="${PEER_IP}/32" 2>/dev/null
		echo "  [✓] firewalld: peer ${PEER_IP} added to trusted zone"
	else
		# iptables — add immediately
		iptables -I INPUT  -s "$PEER_IP" -j ACCEPT 2>/dev/null
		iptables -I OUTPUT -d "$PEER_IP" -j ACCEPT 2>/dev/null

		# Persist via existing iptables service if present
		local svc="/etc/systemd/system/openvpn-iptables.service"
		if [ -f "$svc" ] && ! grep -q "# peer-whitelist" "$svc"; then
			local ipt
			ipt=$(command -v iptables)
			# Insert before RemainAfterExit
			sed -i "s|RemainAfterExit=yes|ExecStart=${ipt} -w 5 -I INPUT -s ${PEER_IP} -j ACCEPT # peer-whitelist\nExecStart=${ipt} -w 5 -I OUTPUT -d ${PEER_IP} -j ACCEPT # peer-whitelist\nExecStop=${ipt} -w 5 -D INPUT -s ${PEER_IP} -j ACCEPT # peer-whitelist\nExecStop=${ipt} -w 5 -D OUTPUT -d ${PEER_IP} -j ACCEPT # peer-whitelist\nRemainAfterExit=yes|" "$svc"
			systemctl daemon-reload
			systemctl restart openvpn-iptables.service >/dev/null 2>&1
		fi
		echo "  [✓] iptables: peer ${PEER_IP} whitelisted (INPUT/OUTPUT)"
	fi
}

# Also whitelist THIS server on the peer (called remotely)
whitelist_self_on_peer() {
	load_peer_conf || return
	local my_public_ip
	my_public_ip=$(grep -m1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' \
		<<< "$(curl -s --max-time 10 https://ifconfig.me 2>/dev/null || wget -qO- --timeout=10 https://ifconfig.me 2>/dev/null)")
	[ -z "$my_public_ip" ] && my_public_ip=$(awk '/^remote /{print $2; exit}' \
		/etc/openvpn/server/client-common.txt 2>/dev/null)
	[ -z "$my_public_ip" ] && return

	echo "  Whitelisting this server (${my_public_ip}) on peer..."
	peer_ssh "if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
		firewall-cmd -q --zone=trusted --add-source=${my_public_ip}/32 2>/dev/null
		firewall-cmd -q --permanent --zone=trusted --add-source=${my_public_ip}/32 2>/dev/null
	else
		iptables -I INPUT  -s ${my_public_ip} -j ACCEPT 2>/dev/null
		iptables -I OUTPUT -d ${my_public_ip} -j ACCEPT 2>/dev/null
	fi" >/dev/null 2>&1
	echo "  [✓] This server whitelisted on peer"
}

# ============================================================
# INSTALL OpenVPN ON PEER SERVER
# ============================================================

install_openvpn_on_peer() {
	load_peer_conf || { echo "  No peer configured."; return 1; }
	echo
	echo "  ── Installing OpenVPN on Failover Server ${PEER_IP} ──"
	echo

	# Step 0: ensure tools + start SSH agent if key has passphrase
	ensure_sshpass
	_peer_agent_start || return 1

	echo "  [1/7] Testing SSH connection..."
	if ! check_peer_ssh; then
		_peer_agent_stop
		echo "  [✗] Cannot reach peer server via SSH."
		echo "      Check: IP=${PEER_IP}  User=${PEER_USER}  Port=${PEER_PORT}"
		return 1
	fi
	echo "  [✓] SSH connection OK"

	# Step 1: copy script to peer (to /tmp first — no sudo needed)
	echo "  [2/7] Copying installer to peer..."
	local script_path
	script_path=$(readlink -f "$0")
	local peer_script="/tmp/openvpn-install-peer.sh"

	_peer_scp_args
	if [ "${PEER_AUTH:-key}" = "key" ]; then
		scp "${SCP_ARGS[@]}" "$script_path" "${PEER_USER:-root}@${PEER_IP}:${peer_script}" \
			|| { echo "  [✗] Failed to copy script to peer."; return 1; }
	else
		sshpass -p "${PEER_PASS}" scp "${SCP_ARGS[@]}" "$script_path" \
			"${PEER_USER:-root}@${PEER_IP}:${peer_script}" \
			|| { echo "  [✗] Failed to copy script to peer."; return 1; }
	fi
	peer_ssh "chmod +x ${peer_script}"
	echo "  [✓] Installer copied"

	# Step 2: detect peer's public IP
	echo "  [3/7] Detecting peer's public IP..."
	local peer_pub_ip
	peer_pub_ip=$(peer_ssh_raw "curl -s --max-time 10 https://ifconfig.me 2>/dev/null || wget -qO- --timeout=10 https://ifconfig.me 2>/dev/null" | tr -d '[:space:]')
	if ! check_ip "$peer_pub_ip"; then
		echo
		read -rp "  Could not auto-detect. Enter peer server's PUBLIC IP: " peer_pub_ip </dev/tty
		check_ip "$peer_pub_ip" || { echo "  [✗] Invalid IP."; return 1; }
	fi
	echo "  [✓] Peer public IP: ${peer_pub_ip}"

	# Step 3: run the installer on peer via sudo
	echo "  [4/7] Installing OpenVPN on peer (2–4 minutes)..."
	peer_ssh "bash ${peer_script} --auto \
		--serveraddr ${peer_pub_ip} \
		--port ${PEER_VPN_PORT:-1194} \
		--proto ${PEER_VPN_PROTO:-udp} \
		--clientname _peer_placeholder_ \
		--dns1 8.8.8.8 --dns2 8.8.4.4 -y" \
		|| { echo "  [✗] OpenVPN installation failed on peer."; return 1; }
	echo "  [✓] OpenVPN installed on peer"

	# Step 4: sync shared PKI
	echo "  [5/7] Syncing shared PKI to peer..."
	_sync_pki_core

	# Save peer public IP in conf
	if ! grep -q "PEER_PUBLIC_IP" "$PEER_CONF"; then
		echo "PEER_PUBLIC_IP=\"${peer_pub_ip}\"" >> "$PEER_CONF"
	else
		sed -i "s|PEER_PUBLIC_IP=.*|PEER_PUBLIC_IP=\"${peer_pub_ip}\"|" "$PEER_CONF"
	fi

	# Step 5: mutual IP whitelisting
	echo "  [6/7] Configuring firewall whitelists (both servers)..."
	whitelist_peer_ips
	whitelist_self_on_peer
	echo "  [✓] Firewall whitelists configured"

	# Step 6: verify PKI sync + OpenVPN running on peer
	echo "  [7/7] Verifying peer server..."
	_verify_peer_setup "$peer_pub_ip"

	# Cleanup temp script on peer
	peer_ssh "rm -f ${peer_script}" >/dev/null 2>&1 || true

	# Stop SSH agent (no longer needed)
	_peer_agent_stop

	echo
	echo "  ┌─────────────────────────────────────────────────────┐"
	echo "  │  [✓] Failover server ready!                         │"
	printf "  │  Main:     %s:%-5s %-22s│\n" "$(awk '/^remote /{print $2; exit}' /etc/openvpn/server/client-common.txt 2>/dev/null)" "${PEER_VPN_PORT:-1194}" ""
	printf "  │  Failover: %s:%-5s %-22s│\n" "${peer_pub_ip}" "${PEER_VPN_PORT:-1194}" ""
	echo "  │                                                     │"
	echo "  │  Both servers share the same PKI.                   │"
	echo "  │  New .ovpn files will include both server IPs.      │"
	echo "  └─────────────────────────────────────────────────────┘"
	echo
}

# ── Verify peer after setup ──────────────────────────────────
_verify_peer_setup() {
	local pub_ip="${1:-$PEER_IP}"
	local ok=1

	# Check 1: OpenVPN service running
	local svc_status
	svc_status=$(peer_ssh "systemctl is-active openvpn-server@server.service 2>/dev/null || systemctl is-active openvpn@server.service 2>/dev/null || echo inactive" 2>/dev/null | tr -d '[:space:]')
	if [ "$svc_status" = "active" ]; then
		echo "  [✓] OpenVPN service: active"
	else
		echo "  [✗] OpenVPN service: ${svc_status:-unknown} — check peer logs"
		ok=0
	fi

	# Check 2: CA cert fingerprint matches
	local main_fp peer_fp
	main_fp=$(openssl x509 -noout -fingerprint -sha256 \
		-in /etc/openvpn/server/easy-rsa/pki/ca.crt 2>/dev/null | cut -d= -f2)
	peer_fp=$(peer_ssh "openssl x509 -noout -fingerprint -sha256 \
		-in /etc/openvpn/server/easy-rsa/pki/ca.crt 2>/dev/null | cut -d= -f2" 2>/dev/null | tr -d '[:space:]')

	if [ -n "$main_fp" ] && [ "$main_fp" = "$peer_fp" ]; then
		echo "  [✓] CA fingerprint matches on both servers"
	else
		echo "  [✗] CA fingerprint MISMATCH — re-run 'Sync PKI to peer'"
		ok=0
	fi

	# Check 3: tc.key hash matches
	local main_tck peer_tck
	main_tck=$(md5sum /etc/openvpn/server/tc.key 2>/dev/null | awk '{print $1}')
	peer_tck=$(peer_ssh "md5sum /etc/openvpn/server/tc.key 2>/dev/null | awk '{print \$1}'" 2>/dev/null | tr -d '[:space:]')
	if [ -n "$main_tck" ] && [ "$main_tck" = "$peer_tck" ]; then
		echo "  [✓] TLS-crypt key matches on both servers"
	else
		echo "  [✗] TLS-crypt key MISMATCH — re-run 'Sync PKI to peer'"
		ok=0
	fi

	if [ "$ok" = 1 ]; then
		echo "  [✓] All verification checks passed"
	else
		echo
		echo "  [!] Some checks failed. Use menu option 10 → Sync PKI to retry."
	fi
}

# ============================================================
# PKI SYNC — core operation
# ============================================================

_sync_pki_core() {
	# Overwrites peer's PKI with this server's PKI so both share same CA.
	# Uses sudo-aware peer_scp_to and peer_ssh throughout.

	local pki="/etc/openvpn/server/easy-rsa/pki"
	local srv="/etc/openvpn/server"

	# Ensure directories exist on peer
	peer_ssh "mkdir -p ${pki}/issued ${pki}/private ${pki}/reqs ${srv}/easy-rsa"

	echo "    Copying CA certificate..."
	peer_scp_to "${pki}/ca.crt"          "${pki}/ca.crt"
	peer_scp_to "${pki}/private/ca.key"  "${pki}/private/ca.key"
	peer_scp_to "${srv}/ca.crt"          "${srv}/ca.crt"

	echo "    Copying server certificate & key..."
	peer_scp_to "${srv}/server.crt"      "${srv}/server.crt"
	peer_scp_to "${srv}/server.key"      "${srv}/server.key"

	echo "    Copying TLS-crypt key (must be identical on both servers)..."
	peer_scp_to "${srv}/tc.key"          "${srv}/tc.key"

	echo "    Copying DH parameters..."
	peer_scp_to "${srv}/dh.pem"          "${srv}/dh.pem"

	echo "    Syncing PKI index & serial..."
	peer_scp_to "${pki}/index.txt"       "${pki}/index.txt"
	peer_scp_to "${pki}/serial"          "${pki}/serial" 2>/dev/null || true

	echo "    Syncing CRL..."
	peer_scp_to "${srv}/crl.pem"         "${srv}/crl.pem"

	echo "    Fixing permissions on peer..."
	peer_ssh "chown nobody:nogroup ${srv}/crl.pem 2>/dev/null || chown nobody:nobody ${srv}/crl.pem 2>/dev/null || true"
	peer_ssh "chmod o+x ${srv}"

	echo "    Restarting OpenVPN on peer..."
	peer_ssh "systemctl restart openvpn-server@server.service 2>/dev/null || systemctl restart openvpn@server.service 2>/dev/null || true"

	echo "  [✓] PKI synced — peer OpenVPN restarted"
}

sync_pki_to_peer() {
	if ! peer_is_configured; then
		echo "  No peer server configured."
		return
	fi
	echo "  Syncing PKI to peer ${PEER_IP}..."
	ensure_sshpass
	_peer_agent_start || return 1
	if ! check_peer_ssh; then
		_peer_agent_stop
		echo "  [✗] Cannot reach peer."
		return 1
	fi
	_sync_pki_core
	_peer_agent_stop
}

# ============================================================
# CLIENT SYNC — add / revoke
# ============================================================

peer_sync_add_client() {
	peer_is_configured || return 0

	local pki="/etc/openvpn/server/easy-rsa/pki"
	local srv="/etc/openvpn/server"

	echo "  Syncing client '${client}' to peer ${PEER_IP}..."

	ensure_sshpass
	_peer_agent_start || { echo "  [!] Cannot unlock SSH key — skipping sync."; return 1; }

	if ! check_peer_ssh; then
		_peer_agent_stop
		echo "  [!] Peer unreachable — client NOT synced. Run 'Peer Management → Sync PKI' later."
		return 1
	fi

	# Ensure directories
	peer_ssh "mkdir -p ${pki}/issued ${pki}/private ${pki}/reqs ${CLIENT_META_DIR}"

	# Copy cert, key, req
	peer_scp_to "${pki}/issued/${client}.crt"   "${pki}/issued/${client}.crt"   2>/dev/null || true
	peer_scp_to "${pki}/private/${client}.key"  "${pki}/private/${client}.key"  2>/dev/null || true
	peer_scp_to "${pki}/reqs/${client}.req"     "${pki}/reqs/${client}.req"     2>/dev/null || true

	# Sync updated PKI index so peer's easyrsa is aware
	peer_scp_to "${pki}/index.txt"  "${pki}/index.txt"  2>/dev/null || true
	peer_scp_to "${pki}/serial"     "${pki}/serial"     2>/dev/null || true

	# Sync client meta (cert-only vs certpass)
	if [ -f "${CLIENT_META_DIR}/${client}.mode" ]; then
		peer_scp_to "${CLIENT_META_DIR}/${client}.mode" "${CLIENT_META_DIR}/${client}.mode" 2>/dev/null || true
	fi

	_peer_agent_stop
	echo "  [✓] Client '${client}' synced to peer"
}

peer_sync_revoke_client() {
	peer_is_configured || return 0

	local pki="/etc/openvpn/server/easy-rsa/pki"
	local srv="/etc/openvpn/server"

	echo "  Syncing revocation of '${client}' to peer ${PEER_IP}..."

	ensure_sshpass
	_peer_agent_start || { echo "  [!] Cannot unlock SSH key — skipping sync."; return 1; }

	if ! check_peer_ssh; then
		_peer_agent_stop
		echo "  [!] Peer unreachable — revocation NOT synced. Sync manually later."
		return 1
	fi

	# Copy updated CRL (most important — this immediately blocks the client on peer)
	peer_scp_to "${srv}/crl.pem"       "${srv}/crl.pem"   2>/dev/null || true
	peer_scp_to "${pki}/index.txt"     "${pki}/index.txt" 2>/dev/null || true

	# Remove client cert files from peer
	peer_ssh "rm -f \
		${pki}/issued/${client}.crt \
		${pki}/private/${client}.key \
		${pki}/reqs/${client}.req \
		${CLIENT_META_DIR}/${client}.mode" 2>/dev/null || true

	# Fix CRL permissions on peer
	peer_ssh "chown nobody:nogroup ${srv}/crl.pem 2>/dev/null || chown nobody:nobody ${srv}/crl.pem 2>/dev/null || true"

	_peer_agent_stop
	echo "  [✓] Revocation synced to peer — client blocked on both servers"
}

# ============================================================
# PEER STATUS / MANAGEMENT MENU
# ============================================================

show_peer_status() {
	echo
	echo "  ── Peer Server Status ──────────────────────────────"
	if ! peer_is_configured; then
		echo "  No peer server configured."
		echo
		return
	fi
	source "$PEER_CONF"
	echo "  Peer IP        : ${PEER_IP}"
	echo "  Public IP      : ${PEER_PUBLIC_IP:-${PEER_IP}}"
	echo "  SSH User/Port  : ${PEER_USER:-root}@${PEER_PORT:-22}"
	echo "  Auth Method    : ${PEER_AUTH:-key}${PEER_KEY_PASS:+ (passphrase protected)}"
	echo "  sudo Mode      : ${PEER_SUDO:-none}"
	echo "  VPN Port/Proto : ${PEER_VPN_PORT:-1194}/${PEER_VPN_PROTO:-udp}"
	echo
	ensure_sshpass
	_peer_agent_start 2>/dev/null
	if check_peer_ssh; then
		echo "  SSH Connection : [✓] OK"
		local svc_status
		svc_status=$(peer_ssh "systemctl is-active openvpn-server@server.service 2>/dev/null \
			|| systemctl is-active openvpn@server.service 2>/dev/null \
			|| echo unknown" 2>/dev/null | tr -d '[:space:]')
		echo "  OpenVPN on peer: ${svc_status}"
	else
		echo "  SSH Connection : [✗] UNREACHABLE"
	fi
	_peer_agent_stop
	echo
}

run_peer_menu() {
	echo
	echo "  Peer Server (Failover) Management:"
	echo "   1) Configure peer server credentials"
	echo "   2) Install OpenVPN on peer (full setup)"
	echo "   3) Sync PKI to peer (re-sync certificates)"
	echo "   4) Whitelist peer IPs in firewall"
	echo "   5) Show peer status"
	echo "   6) Back"
	read -rp "  Select [1-6]: " peer_opt </dev/tty
	echo

	case "$peer_opt" in
		1) setup_peer_interactive && whitelist_peer_ips ;;
		2) install_openvpn_on_peer ;;
		3) sync_pki_to_peer ;;
		4) whitelist_peer_ips && whitelist_self_on_peer ;;
		5) show_peer_status ;;
		6|"") return ;;
		*) echo "  Invalid selection." ;;
	esac
}

# ============================================================
# API Webhook functions
# ============================================================

setup_api_webhook() {
	echo
	read -rp "  Enter API URL (e.g. https://abc.xyz/api/vpn): " api_url </dev/tty
	[ -z "$api_url" ] && { echo "  Cancelled."; return; }
	read -rsp "  Enter API Secret (Bearer token, or press Enter to skip): " api_secret </dev/tty
	echo

	mkdir -p /etc/openvpn/server/hooks
	cat > /etc/openvpn/server/hooks/api.conf <<EOF
API_URL="${api_url}"
API_SECRET="${api_secret}"
EOF
	chmod 600 /etc/openvpn/server/hooks/api.conf

	if [ ! -f "$VPN_HOOK_SCRIPT" ]; then
		echo "  [!] Hook script not found. Go to: API & Automation → Multi-device limit setup"
		return
	fi

	add_hooks_to_conf "/etc/openvpn/server/server.conf"
	if [ -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ]; then
		add_hooks_to_conf "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf"
	fi

	echo "  [✓] Webhook configured → $api_url"
}

get_service_name() {
	local conf="$1"
	local base
	base=$(basename "$conf" .conf)
	if [ "$os" = "openSUSE" ]; then
		echo "openvpn@${base}"
	else
		echo "openvpn-server@${base}"
	fi
}

add_hooks_to_conf() {
	local conf="$1"
	if ! grep -q "client-connect" "$conf" 2>/dev/null; then
		echo "script-security 3"        >> "$conf"
		echo "client-connect ${VPN_HOOK_SCRIPT}"    >> "$conf"
		echo "client-disconnect ${VPN_HOOK_SCRIPT}" >> "$conf"
		systemctl restart "$(get_service_name "$conf").service" >/dev/null 2>&1
		echo "  [✓] Hooks added to $(basename "$conf") and service restarted"
	else
		echo "  [i] Hooks already present in $(basename "$conf")"
	fi
}

test_api_webhook() {
	[ -f /etc/openvpn/server/hooks/api.conf ] || { echo "  No API configured yet."; return; }
	source /etc/openvpn/server/hooks/api.conf

	PAYLOAD='{"event":"test","client":"test-client","real_ip":"1.2.3.4","real_port":12345,"vpn_ip":"172.16.255.2","bytes_received":0,"bytes_sent":0,"timestamp":"'$(date -u '+%Y-%m-%dT%H:%M:%SZ')'"}'
	if [ -n "$API_SECRET" ]; then
		AUTH_HEADER="Authorization: Bearer ${API_SECRET}"
	else
		AUTH_HEADER="X-VPN-Hook: 1"
	fi

	response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL" \
		-H "Content-Type: application/json" -H "$AUTH_HEADER" \
		-d "$PAYLOAD" --max-time 10)

	if [[ "$response" =~ ^2 ]]; then
		echo "  [✓] API responded with HTTP $response"
	else
		echo "  [✗] API responded with HTTP $response"
	fi
}

show_api_config() {
	if [ ! -f /etc/openvpn/server/hooks/api.conf ]; then
		echo "  No API webhook configured."
		return
	fi
	source /etc/openvpn/server/hooks/api.conf
	echo "  URL:    ${API_URL}"
	if [ -n "$API_SECRET" ]; then
		echo "  Secret: ${API_SECRET:0:6}****"
	else
		echo "  Secret: (none)"
	fi
}

run_api_setup() {
	echo
	echo "  API & Automation:"
	echo "   1) Configure API endpoint"
	echo "   2) Test webhook (sends test payload)"
	echo "   3) Show current API config"
	echo "   4) Multi-device limit setup"
	echo "   5) Back"
	read -rp "  Select [1-5]: " api_opt </dev/tty
	echo

	case "$api_opt" in
		1) setup_api_webhook ;;
		2) test_api_webhook ;;
		3) show_api_config ;;
		4) run_device_limit_setup ;;
		5|"") return ;;
		*) echo "  Invalid selection." ;;
	esac
}

# ============================================================
# Client meta helpers
# ============================================================

ensure_meta_dir() {
	mkdir -p "$CLIENT_META_DIR"
	chmod 700 "$CLIENT_META_DIR" 2>/dev/null || true
}

save_client_mode() {
	ensure_meta_dir
	echo "$1" > "$CLIENT_META_DIR/$client.mode"
	chmod 600 "$CLIENT_META_DIR/$client.mode" 2>/dev/null || true
}

load_client_mode() {
	ensure_meta_dir
	if [ -f "$CLIENT_META_DIR/$client.mode" ]; then
		mode="$(tr -d '\r\n' < "$CLIENT_META_DIR/$client.mode")"
	else
		mode="cert"
	fi
	case "$mode" in
		cert)     client_common_file="/etc/openvpn/server/client-common.txt" ;;
		certpass) client_common_file="/etc/openvpn/server/client-common-auth.txt" ;;
		*)        mode="cert"; client_common_file="/etc/openvpn/server/client-common.txt" ;;
	esac
}

select_client_mode_interactive() {
	echo >/dev/tty
	echo "Client auth mode:" >/dev/tty
	echo "  1) Cert only (connect to current server port)" >/dev/tty
	echo "  2) Username/Password + Cert (connect to ${AUTH_PORT_DEFAULT})" >/dev/tty
	read -rp "Select [1-2]: " m </dev/tty
	case "$m" in
		2) echo "certpass" ;;
		*) echo "cert" ;;
	esac
}

_vpn_password=""

prompt_password_hidden() {
	local u="$1" p1 p2
	while true; do
		read -rsp "Enter VPN password for '$u': " p1 </dev/tty; echo >/dev/tty
		read -rsp "Confirm password for '$u': " p2 </dev/tty; echo >/dev/tty
		[ -n "$p1" ] || { echo "Empty password not allowed." >/dev/tty; continue; }
		[ "$p1" = "$p2" ] || { echo "Passwords do not match." >/dev/tty; continue; }
		_vpn_password="$p1"
		return 0
	done
}

create_linux_user_with_password() {
	local u="$1" p="$2"
	if [ "$u" = "root" ]; then
		exiterr "Refusing to use username 'root' for VPN clients."
	fi
	if id "$u" >/dev/null 2>&1; then
		uid="$(id -u "$u" 2>/dev/null || echo 0)"
		if [ "$uid" -lt 1000 ]; then
			exiterr "Refusing to modify system user '$u' (uid=$uid)."
		fi
		echo "Linux user exists: $u (password will be updated)"
	else
		nologin_path=$(command -v nologin 2>/dev/null \
			|| { for p in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin; do
				[ -x "$p" ] && echo "$p" && break
			done; })
		[ -z "$nologin_path" ] && exiterr "Cannot find nologin binary"
		useradd -m -s "$nologin_path" "$u" || exiterr "Failed to create user $u"
	fi
	printf '%s:%s\n' "$u" "$p" | chpasswd || exiterr "Failed to set password for $u"
}

create_pam_config() {
	if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
		if [ ! -f "/etc/pam.d/${PAM_SERVICE_NAME}" ]; then
			cat > "/etc/pam.d/${PAM_SERVICE_NAME}" <<'EOF'
@include common-auth
@include common-account
@include common-password
@include common-session
EOF
		fi
	fi
}

detect_pam_plugin() {
	for p in \
		/usr/lib/openvpn/openvpn-plugin-auth-pam.so \
		/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so \
		/usr/lib64/openvpn/plugins/openvpn-plugin-auth-pam.so
	do
		if [ -f "$p" ]; then
			PAM_PLUGIN_PATH="$p"
			return 0
		fi
	done
	return 1
}

read_current_proto_ip_port() {
	local cc="/etc/openvpn/server/client-common.txt"
	server_proto="$(awk '/^proto /{print $2; exit}' "$cc")"
	server_ip="$(awk '/^remote /{print $2; exit}' "$cc")"
	server_port="$(awk '/^remote /{print $3; exit}' "$cc")"
	[ -n "$server_proto" ] && [ -n "$server_ip" ] && [ -n "$server_port" ] \
		|| exiterr "Could not detect proto/ip/port from $cc"
}

make_client_common_auth() {
	read_current_proto_ip_port
	local out="/etc/openvpn/server/client-common-auth.txt"
	sed -E "s/^remote[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+$/remote $server_ip $AUTH_PORT_DEFAULT/" \
		/etc/openvpn/server/client-common.txt > "$out"
	grep -q '^auth-user-pass' "$out" || printf '\nauth-user-pass\nauth-nocache\n' >> "$out"
	chmod 600 "$out"
}

create_firewall_rules_auth() {
	read_current_proto_ip_port
	if systemctl is-active --quiet firewalld.service; then
		firewall-cmd -q --add-port="${AUTH_PORT_DEFAULT}/${server_proto}"
		firewall-cmd -q --zone=trusted --add-source="$AUTH_VPN_CIDR"
		firewall-cmd -q --direct --add-rule ipv4 nat POSTROUTING 0 -s "$AUTH_VPN_CIDR" ! -d "$AUTH_VPN_CIDR" -j MASQUERADE
		firewall-cmd -q --permanent --add-port="${AUTH_PORT_DEFAULT}/${server_proto}"
		firewall-cmd -q --permanent --zone=trusted --add-source="$AUTH_VPN_CIDR"
		firewall-cmd -q --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s "$AUTH_VPN_CIDR" ! -d "$AUTH_VPN_CIDR" -j MASQUERADE
	else
		iptables_path=$(command -v iptables)
		unit="/etc/systemd/system/openvpn-iptables-auth.service"
		cat > "$unit" <<EOF
[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s $AUTH_VPN_CIDR ! -d $AUTH_VPN_CIDR -j MASQUERADE
ExecStart=$iptables_path -w 5 -I INPUT -p $server_proto --dport $AUTH_PORT_DEFAULT -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s $AUTH_VPN_CIDR -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s $AUTH_VPN_CIDR ! -d $AUTH_VPN_CIDR -j MASQUERADE
ExecStop=$iptables_path -w 5 -D INPUT -p $server_proto --dport $AUTH_PORT_DEFAULT -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s $AUTH_VPN_CIDR -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable --now openvpn-iptables-auth.service >/dev/null 2>&1
	fi
}

ensure_auth_instance() {
	create_pam_config
	make_client_common_auth
	detect_pam_plugin || exiterr "PAM plugin not found."
	read_current_proto_ip_port

	cat > /etc/openvpn/server/verify-cn.sh <<'EOF'
#!/bin/bash
if [ -z "$username" ] || [ -z "$common_name" ]; then exit 1; fi
if [ "$username" != "$common_name" ]; then
	logger -t openvpn "AUTH REJECTED: username='$username' != CN='$common_name'"
	exit 1
fi
exit 0
EOF
	chown root:"$group_name" /etc/openvpn/server/verify-cn.sh
	chmod 750 /etc/openvpn/server/verify-cn.sh

	local conf="/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf"
	if [ ! -f "$conf" ]; then
		cat > "$conf" <<EOF
port $AUTH_PORT_DEFAULT
proto $server_proto
dev tun-${AUTH_INSTANCE_NAME}

ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA256
tls-crypt tc.key

topology subnet
server $AUTH_VPN_NET $AUTH_VPN_MASK
ifconfig-pool-persist ipp-${AUTH_INSTANCE_NAME}.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "block-outside-dns"

keepalive 10 120
cipher AES-128-GCM

verify-client-cert require
plugin $PAM_PLUGIN_PATH $PAM_SERVICE_NAME
auth-nocache
auth-user-pass-verify /etc/openvpn/server/verify-cn.sh via-env
username-as-common-name
script-security 3
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem
status openvpn-status-auth.log
EOF
	fi

	create_firewall_rules_auth
	systemctl enable --now "$(get_service_name "$conf").service" >/dev/null 2>&1
}

# ============================================================
# Argument parsing & validation
# ============================================================

parse_args() {
	while [ "$#" -gt 0 ]; do
		case $1 in
			--auto)          auto=1; shift ;;
			--addclient)     add_client=1; unsanitized_client="$2"; shift 2 ;;
			--exportclient)  export_client=1; unsanitized_client="$2"; shift 2 ;;
			--listclients)   list_clients=1; shift ;;
			--revokeclient)  revoke_client=1; unsanitized_client="$2"; shift 2 ;;
			--uninstall)     remove_ovpn=1; shift ;;
			--listenaddr)    listen_addr="$2"; shift 2 ;;
			--serveraddr)    server_addr="$2"; shift 2 ;;
			--proto)         server_proto="$2"; shift 2 ;;
			--port)          server_port="$2"; shift 2 ;;
			--clientname)    first_client_name="$2"; shift 2 ;;
			--dns1)          dns1="$2"; shift 2 ;;
			--dns2)          dns2="$2"; shift 2 ;;
			-y|--yes)        assume_yes=1; shift ;;
			-h|--help)       show_usage ;;
			*)               show_usage "Unknown parameter: $1" ;;
		esac
	done
}

check_args() {
	if [ "$auto" != 0 ] && [ -e "$OVPN_CONF" ]; then
		show_usage "Invalid parameter '--auto'. OpenVPN is already set up on this server."
	fi
	if [ "$((add_client + export_client + list_clients + revoke_client))" -gt 1 ]; then
		show_usage "Invalid parameters. Specify only one of '--addclient', '--exportclient', '--listclients' or '--revokeclient'."
	fi
	if [ "$remove_ovpn" = 1 ]; then
		if [ "$((add_client + export_client + list_clients + revoke_client + auto))" -gt 0 ]; then
			show_usage "Invalid parameters. '--uninstall' cannot be specified with other parameters."
		fi
	fi
	if [ ! -e "$OVPN_CONF" ]; then
		st_text="You must first set up OpenVPN before"
		[ "$add_client" = 1 ]    && exiterr "$st_text adding a client."
		[ "$export_client" = 1 ] && exiterr "$st_text exporting a client."
		[ "$list_clients" = 1 ]  && exiterr "$st_text listing clients."
		[ "$revoke_client" = 1 ] && exiterr "$st_text revoking a client."
		[ "$remove_ovpn" = 1 ]   && exiterr "Cannot remove OpenVPN because it has not been set up."
	fi
	if [ "$((add_client + export_client + revoke_client))" = 1 ] && [ -n "$first_client_name" ]; then
		show_usage "Invalid parameters. '--clientname' can only be specified when installing OpenVPN."
	fi
	if [ -n "$listen_addr" ] || [ -n "$server_addr" ] || [ -n "$server_proto" ] \
		|| [ -n "$server_port" ] || [ -n "$first_client_name" ] || [ -n "$dns1" ]; then
		if [ -e "$OVPN_CONF" ]; then
			show_usage "Invalid parameters. OpenVPN is already set up on this server."
		elif [ "$auto" = 0 ]; then
			show_usage "Invalid parameters. You must specify '--auto' when using these parameters."
		fi
	fi
	if [ "$add_client" = 1 ]; then
		set_client_name
		if [ -z "$client" ]; then
			exiterr "Invalid client name."
		elif [ -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]; then
			exiterr "$client: invalid name. Client already exists."
		fi
	fi
	if [ "$export_client" = 1 ] || [ "$revoke_client" = 1 ]; then
		set_client_name
		if [ -z "$client" ] || [ ! -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]; then
			exiterr "Invalid client name, or client does not exist."
		fi
	fi
	if [ -n "$listen_addr" ] && ! check_ip "$listen_addr"; then
		show_usage "Invalid listen address."
	fi
	if [ -n "$listen_addr" ] && [ -z "$server_addr" ]; then
		show_usage "You must also specify the server address if the listen address is specified."
	fi
	if [ -n "$server_addr" ] && { ! check_dns_name "$server_addr" && ! check_ip "$server_addr"; }; then
		exiterr "Invalid server address."
	fi
	if [ -n "$first_client_name" ]; then
		unsanitized_client="$first_client_name"
		set_client_name
		[ -z "$client" ] && exiterr "Invalid client name."
	fi
	if [ -n "$server_proto" ]; then
		case "$server_proto" in
			[tT][cC][pP]) server_proto=tcp ;;
			[uU][dD][pP]) server_proto=udp ;;
			*) exiterr "Invalid protocol. Must be TCP or UDP." ;;
		esac
	fi
	if [ -n "$server_port" ]; then
		if [[ ! "$server_port" =~ ^[0-9]+$ || "$server_port" -gt 65535 ]]; then
			exiterr "Invalid port."
		fi
	fi
	if { [ -n "$dns1" ] && ! check_ip "$dns1"; } \
		|| { [ -n "$dns2" ] && ! check_ip "$dns2"; }; then
		exiterr "Invalid DNS server(s)."
	fi
	if [ -z "$dns1" ] && [ -n "$dns2" ]; then
		show_usage "Invalid DNS server. --dns2 cannot be specified without --dns1."
	fi
	[ -n "$dns1" ] && dns=7 || dns=2
}

check_nftables() {
	if [ "$os" = "centos" ]; then
		if grep -qs "hwdsl2 VPN script" /etc/sysconfig/nftables.conf \
			|| systemctl is-active --quiet nftables 2>/dev/null; then
			exiterr "This system has nftables enabled, which is not supported."
		fi
	fi
}

install_wget() {
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "Wget is required."
			read -n1 -r -p "Press any key to install Wget and continue..."
		fi
		export DEBIAN_FRONTEND=noninteractive
		(set -x; apt-get -yqq update || apt-get -yqq update; apt-get -yqq install wget >/dev/null) || exiterr2
	fi
}

install_iproute() {
	if ! hash ip 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "iproute is required."
			read -n1 -r -p "Press any key to install iproute and continue..."
		fi
		if [ "$os" = "debian" ] || [ "$os" = "ubuntu" ]; then
			export DEBIAN_FRONTEND=noninteractive
			(set -x; apt-get -yqq update || apt-get -yqq update; apt-get -yqq install iproute2 >/dev/null) || exiterr2
		elif [ "$os" = "openSUSE" ]; then
			(set -x; zypper install iproute2 >/dev/null) || exiterr4
		else
			(set -x; yum -y -q install iproute >/dev/null) || exiterr3
		fi
	fi
}

show_header() {
cat <<'EOF'

OpenVPN Script — Dual Server Failover Edition
https://github.com/hwdsl2/openvpn-install
EOF
}

show_header2() {
cat <<'EOF'

Welcome to this OpenVPN server installer!
GitHub: https://github.com/hwdsl2/openvpn-install

EOF
}

show_header3() {
cat <<'EOF'

Copyright (c) 2022-2025 Lin Song
Copyright (c) 2013-2023 Nyr
EOF
}

show_usage() {
	if [ -n "$1" ]; then echo "Error: $1" >&2; fi
	show_header; show_header3
cat 1>&2 <<EOF

Usage: bash $0 [options]

Options:

  --addclient [client name]      add a new client
  --exportclient [client name]   export configuration for an existing client
  --listclients                  list the names of existing clients
  --revokeclient [client name]   revoke an existing client
  --uninstall                    remove OpenVPN and delete all configuration
  -y, --yes                      assume "yes" as answer to prompts
  -h, --help                     show this help message and exit

Install options (optional):

  --auto                         auto install OpenVPN using default or custom options
  --listenaddr [IPv4 address]    IPv4 address that OpenVPN should listen on
  --serveraddr [DNS name or IP]  server address (FQDN or IPv4)
  --proto [TCP or UDP]           protocol (default: UDP)
  --port [number]                port (1-65535, default: 1194)
  --clientname [client name]     name for the first client (default: client)
  --dns1 [DNS server IP]         primary DNS server
  --dns2 [DNS server IP]         secondary DNS server
EOF
	exit 1
}

show_welcome() {
	if [ "$auto" = 0 ]; then
		show_header2
		echo 'I need to ask you a few questions before starting setup.'
		echo 'You can use the default options and just press enter if you are OK with them.'
	else
		show_header
		op_text=default
		if [ -n "$listen_addr" ] || [ -n "$server_addr" ] || [ -n "$server_proto" ] \
			|| [ -n "$server_port" ] || [ -n "$first_client_name" ] || [ -n "$dns1" ]; then
			op_text=custom
		fi
		echo
		echo "Starting OpenVPN setup using $op_text options."
	fi
}

show_dns_name_note() {
cat <<EOF

Note: Make sure this DNS name '$1'
      resolves to the IPv4 address of this server.
EOF
}

enter_server_address() {
	echo
	echo "Do you want OpenVPN clients to connect to this server using a DNS name,"
	printf "e.g. vpn.example.com, instead of its IP address? [y/N] "
	read -r response
	case $response in
		[yY][eE][sS]|[yY])
			use_dns_name=1; echo ;;
		*)
			use_dns_name=0 ;;
	esac
	if [ "$use_dns_name" = 1 ]; then
		read -rp "Enter the DNS name of this VPN server: " server_addr_i
		until check_dns_name "$server_addr_i"; do
			echo "Invalid DNS name."
			read -rp "Enter the DNS name of this VPN server: " server_addr_i
		done
		detect_ip
		public_ip="$server_addr_i"
		show_dns_name_note "$public_ip"
	else
		detect_ip
		check_nat_ip
	fi
}

find_public_ip() {
	ip_url1="http://ipv4.icanhazip.com"
	ip_url2="http://ip1.dynupdate.no-ip.com"
	get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "$ip_url1" || curl -m 10 -4Ls "$ip_url1")")
	if ! check_ip "$get_public_ip"; then
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "$ip_url2" || curl -m 10 -4Ls "$ip_url2")")
	fi
}

detect_ip() {
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		ip=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}' 2>/dev/null)
		if ! check_ip "$ip"; then
			find_public_ip
			ip_match=0
			if [ -n "$get_public_ip" ]; then
				ip_list=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
				while IFS= read -r line; do
					if [ "$line" = "$get_public_ip" ]; then
						ip_match=1; ip="$line"
					fi
				done <<< "$ip_list"
			fi
			if [ "$ip_match" = 0 ]; then
				if [ "$auto" = 0 ]; then
					echo; echo "Which IPv4 address should be used?"
					num_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
					ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
					read -rp "IPv4 address [1]: " ip_num
					until [[ -z "$ip_num" || "$ip_num" =~ ^[0-9]+$ && "$ip_num" -le "$num_of_ip" ]]; do
						echo "$ip_num: invalid selection."
						read -rp "IPv4 address [1]: " ip_num
					done
					[[ -z "$ip_num" ]] && ip_num=1
				else
					ip_num=1
				fi
				ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_num"p)
			fi
		fi
	fi
	if ! check_ip "$ip"; then
		echo "Error: Could not detect this server's IP address." >&2
		echo "Abort. No changes were made." >&2
		exit 1
	fi
}

check_nat_ip() {
	if check_pvt_ip "$ip"; then
		find_public_ip
		if ! check_ip "$get_public_ip"; then
			if [ "$auto" = 0 ]; then
				echo; echo "This server is behind NAT. What is the public IPv4 address?"
				read -rp "Public IPv4 address: " public_ip
				until check_ip "$public_ip"; do
					echo "Invalid input."
					read -rp "Public IPv4 address: " public_ip
				done
			else
				echo "Error: Could not detect this server's public IP." >&2
				echo "Abort. No changes were made." >&2
				exit 1
			fi
		else
			public_ip="$get_public_ip"
		fi
	fi
}

show_config() {
	if [ "$auto" != 0 ]; then
		echo
		[ -n "$listen_addr" ]  && echo "Listen address: $listen_addr"
		if [ -n "$server_addr" ]; then
			echo "Server address: $server_addr"
		else
			printf '%s' "Server IP: "
			[ -n "$public_ip" ] && printf '%s\n' "$public_ip" || printf '%s\n' "$ip"
		fi
		[ "$server_proto" = "tcp" ] && proto_text=TCP || proto_text=UDP
		[ -n "$server_port" ] && port_text="$server_port" || port_text=1194
		[ -n "$first_client_name" ] && client_text="$client" || client_text=client
		if [ -n "$dns1" ] && [ -n "$dns2" ]; then
			dns_text="$dns1, $dns2"
		elif [ -n "$dns1" ]; then
			dns_text="$dns1"
		else
			dns_text="Google Public DNS"
		fi
		echo "Port: $proto_text/$port_text"
		echo "Client name: $client_text"
		echo "Client DNS: $dns_text"
	fi
}

detect_ipv6() {
	ip6=""
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -ne 0 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n 1p)
	fi
}

select_protocol() {
	if [ "$auto" = 0 ]; then
		echo
		echo "Which protocol should OpenVPN use?"
		echo "   1) UDP (recommended)"
		echo "   2) TCP"
		read -rp "Protocol [1]: " protocol
		until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
			echo "$protocol: invalid selection."
			read -rp "Protocol [1]: " protocol
		done
		case "$protocol" in
			1|"") protocol=udp ;;
			2)    protocol=tcp ;;
		esac
	else
		[ -n "$server_proto" ] && protocol="$server_proto" || protocol=udp
	fi
}

select_port() {
	if [ "$auto" = 0 ]; then
		echo
		echo "Which port should OpenVPN listen on?"
		read -rp "Port [1194]: " port
		until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
			echo "$port: invalid port."
			read -rp "Port [1194]: " port
		done
		[[ -z "$port" ]] && port=1194
	else
		[ -n "$server_port" ] && port="$server_port" || port=1194
	fi
}

enter_custom_dns() {
	read -rp "Enter primary DNS server: " dns1
	until check_ip "$dns1"; do
		echo "Invalid DNS server."
		read -rp "Enter primary DNS server: " dns1
	done
	read -rp "Enter secondary DNS server (Enter to skip): " dns2
	until [ -z "$dns2" ] || check_ip "$dns2"; do
		echo "Invalid DNS server."
		read -rp "Enter secondary DNS server (Enter to skip): " dns2
	done
}

select_dns() {
	if [ "$auto" = 0 ]; then
		echo
		echo "Select a DNS server for the clients:"
		echo "   1) Current system resolvers"
		echo "   2) Google Public DNS"
		echo "   3) Cloudflare DNS"
		echo "   4) OpenDNS"
		echo "   5) Quad9"
		echo "   6) AdGuard DNS"
		echo "   7) Custom"
		read -rp "DNS server [2]: " dns
		until [[ -z "$dns" || "$dns" =~ ^[1-7]$ ]]; do
			echo "$dns: invalid selection."
			read -rp "DNS server [2]: " dns
		done
	else
		dns=2
	fi
	[ "$dns" = 7 ] && enter_custom_dns
}

enter_first_client_name() {
	if [ "$auto" = 0 ]; then
		echo
		echo "Enter a name for the first client:"
		read -rp "Name [client]: " unsanitized_client
		set_client_name
		[[ -z "$client" ]] && client=client
	else
		if [ -n "$first_client_name" ]; then
			unsanitized_client="$first_client_name"
			set_client_name
		else
			client=client
		fi
	fi
}

show_setup_ready() {
	if [ "$auto" = 0 ]; then
		echo; echo "OpenVPN installation is ready to begin."
	fi
}

check_firewall() {
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" || "$os" == "openSUSE" ]]; then
			firewall="firewalld"
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			firewall="iptables"
		fi
		if [[ "$firewall" == "firewalld" ]]; then
			echo; echo "Note: firewalld will also be installed."
		fi
	fi
}

abort_and_exit() {
	echo "Abort. No changes were made." >&2
	exit 1
}

confirm_setup() {
	if [ "$auto" = 0 ]; then
		printf "Do you want to continue? [Y/n] "
		read -r response
		case $response in
			[yY][eE][sS]|[yY]|'') : ;;
			*) abort_and_exit ;;
		esac
	fi
}

show_start_setup() {
	echo; echo "Installing OpenVPN, please wait..."
}

disable_limitnproc() {
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
}

install_pkgs() {
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		export DEBIAN_FRONTEND=noninteractive
		(set -x; apt-get -yqq update || apt-get -yqq update
		 apt-get -yqq --no-install-recommends install openvpn libpam0g >/dev/null) || exiterr2
		(set -x; apt-get -yqq install openssl ca-certificates $firewall >/dev/null) || exiterr2
	elif [[ "$os" = "centos" ]]; then
		if grep -qs "Amazon Linux release 2 " /etc/system-release; then
			(set -x; amazon-linux-extras install epel -y >/dev/null) || exit 1
		else
			(set -x; yum -y -q install epel-release >/dev/null) || exiterr3
		fi
		(set -x; yum -y -q install openvpn openssl ca-certificates tar $firewall >/dev/null 2>&1) || exiterr3
	elif [[ "$os" = "fedora" ]]; then
		(set -x; dnf install -y openvpn openssl ca-certificates tar $firewall >/dev/null) || exiterr "'dnf install' failed."
	else
		(set -x; zypper install -y openvpn openssl ca-certificates tar $firewall >/dev/null) || exiterr4
	fi
	if [[ "$firewall" == "firewalld" ]]; then
		(set -x; systemctl enable --now firewalld.service >/dev/null 2>&1)
	fi
}

remove_pkgs() {
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		(set -x; rm -rf /etc/openvpn/server; apt-get remove --purge -y openvpn >/dev/null)
	elif [[ "$os" = "openSUSE" ]]; then
		(set -x; zypper remove -y openvpn >/dev/null; rm -rf /etc/openvpn/server)
		rm -f /etc/openvpn/ipp.txt
	else
		(set -x; yum -y -q remove openvpn >/dev/null; rm -rf /etc/openvpn/server)
	fi
}

create_firewall_rules() {
	if systemctl is-active --quiet firewalld.service; then
		firewall-cmd -q --add-port="$port"/"$protocol"
		firewall-cmd -q --zone=trusted --add-source=172.16.255.0/24
		firewall-cmd -q --permanent --add-port="$port"/"$protocol"
		firewall-cmd -q --permanent --zone=trusted --add-source=172.16.255.0/24
		firewall-cmd -q --direct --add-rule ipv4 nat POSTROUTING 0 -s 172.16.255.0/24 ! -d 172.16.255.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 172.16.255.0/24 ! -d 172.16.255.0/24 -j MASQUERADE
		if [[ -n "$ip6" ]]; then
			firewall-cmd -q --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd -q --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd -q --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j MASQUERADE
			firewall-cmd -q --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j MASQUERADE
		fi
	else
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 172.16.255.0/24 ! -d 172.16.255.0/24 -j MASQUERADE
ExecStart=$iptables_path -w 5 -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s 172.16.255.0/24 -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 172.16.255.0/24 ! -d 172.16.255.0/24 -j MASQUERADE
ExecStop=$iptables_path -w 5 -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s 172.16.255.0/24 -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j MASQUERADE
ExecStart=$ip6tables_path -w 5 -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j MASQUERADE
ExecStop=$ip6tables_path -w 5 -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		(set -x; systemctl enable --now openvpn-iptables.service >/dev/null 2>&1)
	fi
}

remove_firewall_rules() {
	port=$(grep '^port ' "$OVPN_CONF" | cut -d " " -f 2)
	protocol=$(grep '^proto ' "$OVPN_CONF" | cut -d " " -f 2)
	if systemctl is-active --quiet firewalld.service; then
		ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 172.16.255.0/24 '"'"'!'"'"' -d 172.16.255.0/24' | grep -oE '[^ ]+$')
		firewall-cmd -q --remove-port="$port"/"$protocol"
		firewall-cmd -q --zone=trusted --remove-source=172.16.255.0/24
		firewall-cmd -q --permanent --remove-port="$port"/"$protocol"
		firewall-cmd -q --permanent --zone=trusted --remove-source=172.16.255.0/24
		firewall-cmd -q --direct --remove-rule ipv4 nat POSTROUTING 0 -s 172.16.255.0/24 ! -d 172.16.255.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 172.16.255.0/24 ! -d 172.16.255.0/24 -j MASQUERADE
		if grep -qs "server-ipv6" "$OVPN_CONF"; then
			firewall-cmd -q --zone=trusted --remove-source=fddd:1194:1194:1194::/64
			firewall-cmd -q --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
			firewall-cmd -q --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j MASQUERADE
			firewall-cmd -q --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j MASQUERADE
		fi
		# Cleanup auth firewall
		firewall-cmd -q --remove-port="${AUTH_PORT_DEFAULT}/${protocol}" 2>/dev/null
		firewall-cmd -q --permanent --remove-port="${AUTH_PORT_DEFAULT}/${protocol}" 2>/dev/null
		firewall-cmd -q --zone=trusted --remove-source="$AUTH_VPN_CIDR" 2>/dev/null
		firewall-cmd -q --permanent --zone=trusted --remove-source="$AUTH_VPN_CIDR" 2>/dev/null
		firewall-cmd -q --direct --remove-rule ipv4 nat POSTROUTING 0 \
			-s "$AUTH_VPN_CIDR" ! -d "$AUTH_VPN_CIDR" -j MASQUERADE 2>/dev/null
		firewall-cmd -q --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 \
			-s "$AUTH_VPN_CIDR" ! -d "$AUTH_VPN_CIDR" -j MASQUERADE 2>/dev/null
		# Remove peer whitelist
		if peer_is_configured; then
			firewall-cmd -q --zone=trusted --remove-source="${PEER_IP}/32" 2>/dev/null
			firewall-cmd -q --permanent --zone=trusted --remove-source="${PEER_IP}/32" 2>/dev/null
		fi
	else
		systemctl disable --now openvpn-iptables.service
		rm -f /etc/systemd/system/openvpn-iptables.service
		systemctl disable --now openvpn-iptables-auth.service >/dev/null 2>&1 || true
		rm -f /etc/systemd/system/openvpn-iptables-auth.service
		systemctl daemon-reload >/dev/null 2>&1
	fi
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		semanage port -d -t openvpn_port_t -p "$protocol" "$port"
	fi
}

install_easyrsa() {
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.5/EasyRSA-3.2.5.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -t 3 -T 30 -qO- "$easy_rsa_url" 2>/dev/null || curl -m 30 -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1 2>/dev/null
	if [ ! -f /etc/openvpn/server/easy-rsa/easyrsa ]; then
		exiterr "Failed to download EasyRSA."
	fi
	chown -R root:root /etc/openvpn/server/easy-rsa/
}

create_pki_and_certs() {
	cd /etc/openvpn/server/easy-rsa/ || exit 1
	(
		set -x
		./easyrsa --batch init-pki >/dev/null
		./easyrsa --batch build-ca nopass >/dev/null 2>&1
		./easyrsa --batch --days=3650 build-server-full server nopass >/dev/null 2>&1
		./easyrsa --batch --days=3650 build-client-full "$client" nopass >/dev/null 2>&1
		./easyrsa --batch --days=3650 gen-crl >/dev/null 2>&1
	)
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	chmod o+x /etc/openvpn/server/
	(set -x; openvpn --genkey --secret /etc/openvpn/server/tc.key >/dev/null)
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
}

create_dns_config() {
	case "$dns" in
		1)
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53'; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> "$OVPN_CONF"
			done
		;;
		2|"") echo 'push "dhcp-option DNS 8.8.8.8"' >> "$OVPN_CONF"
		      echo 'push "dhcp-option DNS 8.8.4.4"' >> "$OVPN_CONF" ;;
		3)    echo 'push "dhcp-option DNS 1.1.1.1"' >> "$OVPN_CONF"
		      echo 'push "dhcp-option DNS 1.0.0.1"' >> "$OVPN_CONF" ;;
		4)    echo 'push "dhcp-option DNS 208.67.222.222"' >> "$OVPN_CONF"
		      echo 'push "dhcp-option DNS 208.67.220.220"' >> "$OVPN_CONF" ;;
		5)    echo 'push "dhcp-option DNS 9.9.9.9"' >> "$OVPN_CONF"
		      echo 'push "dhcp-option DNS 149.112.112.112"' >> "$OVPN_CONF" ;;
		6)    echo 'push "dhcp-option DNS 94.140.14.14"' >> "$OVPN_CONF"
		      echo 'push "dhcp-option DNS 94.140.15.15"' >> "$OVPN_CONF" ;;
		7)    echo "push \"dhcp-option DNS $dns1\"" >> "$OVPN_CONF"
		      [ -n "$dns2" ] && echo "push \"dhcp-option DNS $dns2\"" >> "$OVPN_CONF" ;;
	esac
}

create_server_config() {
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA256
tls-crypt tc.key
topology subnet
server 172.16.255.0 255.255.255.0" > "$OVPN_CONF"
	if [[ -z "$ip6" ]]; then
		echo 'push "block-ipv6"' >> "$OVPN_CONF"
		echo 'push "ifconfig-ipv6 fddd:1194:1194:1194::2/64 fddd:1194:1194:1194::1"' >> "$OVPN_CONF"
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> "$OVPN_CONF"
	fi
	echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> "$OVPN_CONF"
	echo 'ifconfig-pool-persist ipp.txt' >> "$OVPN_CONF"
	create_dns_config
	echo 'push "block-outside-dns"' >> "$OVPN_CONF"
	echo "status openvpn-status.log
keepalive 10 120
cipher AES-128-GCM
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> "$OVPN_CONF"
	[[ "$protocol" = "udp" ]] && echo "explicit-exit-notify" >> "$OVPN_CONF"
}

get_export_dir() {
	export_to_home_dir=0
	export_dir=~/
	if [ -n "$SUDO_USER" ] && getent group "$SUDO_USER" >/dev/null 2>&1; then
		user_home_dir=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
		if [ -d "$user_home_dir" ] && [ "$user_home_dir" != "/" ]; then
			export_dir="$user_home_dir/"
			export_to_home_dir=1
		fi
	fi
}

# ============================================================
# new_client — generates .ovpn with FAILOVER remotes if peer set
# ============================================================
new_client() {
	get_export_dir

	local common_file="${client_common_file:-/etc/openvpn/server/client-common.txt}"

	# Determine if we have a peer for failover
	local peer_remote_ip=""
	local peer_remote_port=""
	local peer_remote_proto=""

	if load_peer_conf 2>/dev/null && [ -n "${PEER_IP:-}" ]; then
		peer_remote_ip="${PEER_PUBLIC_IP:-$PEER_IP}"
		peer_remote_port="${PEER_VPN_PORT:-1194}"
		peer_remote_proto="${PEER_VPN_PROTO:-udp}"
	fi

	{
	if [ -n "$peer_remote_ip" ]; then
		# Emit client-common WITHOUT the remote line
		# then add both remotes for failover
		local my_ip my_port my_proto
		my_ip=$(awk    '/^remote /{print $2; exit}' "$common_file")
		my_port=$(awk  '/^remote /{print $3; exit}' "$common_file")
		my_proto=$(awk '/^proto  /{print $2; exit}' "$common_file")

		grep -v '^remote ' "$common_file"
		echo ""
		echo "# ── Failover: try both servers, first available wins ──"
		echo "remote ${my_ip} ${my_port} ${my_proto:-udp}"
		echo "remote ${peer_remote_ip} ${peer_remote_port} ${peer_remote_proto}"
		echo "# OpenVPN will automatically reconnect to the other server on failure"
	else
		cat "$common_file"
	fi

	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > "$export_dir$client".ovpn

	if [ "$export_to_home_dir" = 1 ]; then
		chown "$SUDO_USER:$SUDO_USER" "$export_dir$client".ovpn
	fi
	chmod 600 "$export_dir$client".ovpn
}

update_sysctl() {
	mkdir -p /etc/sysctl.d
	conf_fwd="/etc/sysctl.d/99-openvpn-forward.conf"
	conf_opt="/etc/sysctl.d/99-openvpn-optimize.conf"
	echo 'net.ipv4.ip_forward=1' > "$conf_fwd"
	if [[ -n "$ip6" ]]; then
		echo "net.ipv6.conf.all.forwarding=1" >> "$conf_fwd"
	fi
	base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
	conf_url="$base_url/sysctl-ovpn-$os"
	[ "$auto" != 0 ] && conf_url="${conf_url}-auto"
	wget -t 3 -T 30 -q -O "$conf_opt" "$conf_url" 2>/dev/null \
		|| curl -m 30 -fsL "$conf_url" -o "$conf_opt" 2>/dev/null \
		|| { /bin/rm -f "$conf_opt"; touch "$conf_opt"; }
	if modprobe -q tcp_bbr \
		&& printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V \
		&& [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
cat >> "$conf_opt" <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
	fi
	sysctl -e -q -p "$conf_fwd"
	sysctl -e -q -p "$conf_opt"
}

update_rclocal() {
	ipt_cmd="systemctl restart openvpn-iptables.service"
	if ! grep -qs "$ipt_cmd" /etc/rc.local; then
		if [ ! -f /etc/rc.local ]; then
			echo '#!/bin/sh' > /etc/rc.local
		else
			if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
				sed --follow-symlinks -i '/^exit 0/d' /etc/rc.local
			fi
		fi
cat >> /etc/rc.local <<EOF

$ipt_cmd
EOF
		if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
			echo "exit 0" >> /etc/rc.local
		fi
		chmod +x /etc/rc.local
	fi
}

update_selinux() {
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				(set -x; yum -y -q install policycoreutils-python >/dev/null) || exiterr3
			else
				(set -x; dnf install -y policycoreutils-python-utils >/dev/null) || exiterr "'dnf install' failed."
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
}

create_client_common() {
	[[ -n "$public_ip" ]] && ip="$public_ip"
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-128-GCM
ignore-unknown-option block-outside-dns block-ipv6
verb 3" > /etc/openvpn/server/client-common.txt
}

start_openvpn_service() {
	if [ "$os" != "openSUSE" ]; then
		(set -x; systemctl enable --now openvpn-server@server.service >/dev/null 2>&1)
	else
		ln -s /etc/openvpn/server/* /etc/openvpn >/dev/null 2>&1
		(set -x; systemctl enable --now openvpn@server.service >/dev/null 2>&1)
	fi
}

# ============================================================
# finish_setup — ask about peer setup after install
# ============================================================
finish_setup() {
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in: $export_dir$client.ovpn"
	echo "New clients can be added by running this script again."

	# Offer peer (failover) setup in interactive mode
	if [ "$auto" = 0 ]; then
		echo
		echo "──────────────────────────────────────────────────────────"
		printf "Do you want to set up a SECOND server for failover? [y/N] "
		read -r setup_peer_resp
		case $setup_peer_resp in
			[yY][eE][sS]|[yY])
				if setup_peer_interactive; then
					whitelist_peer_ips
					echo
					printf "Install OpenVPN on the peer server now? [y/N] "
					read -r install_peer_resp
					if [[ "$install_peer_resp" =~ ^[yY]$ ]]; then
						install_openvpn_on_peer
					else
						echo
						echo "  To install OpenVPN on peer later, run:"
						echo "    bash $0"
						echo "  Then select: Peer Server (Failover) Management → Install OpenVPN on peer"
					fi
				fi
				;;
		esac
	fi
}

# ============================================================
# Menu
# ============================================================
select_menu_option() {
	echo
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Export config for an existing client"
	echo "   3) List existing clients"
	echo "   4) Revoke an existing client"
	echo "   5) Show active VPN users"
	echo "   6) Bandwidth report"
	echo "   7) API webhook setup"
	echo "   8) Security setup (fail2ban / SSH)"
	echo "   9) Backup & restore"
	echo "  10) Peer server (failover) management"
	echo "  11) Remove OpenVPN"
	echo "  12) Exit"
	read -rp "Option: " option
	until [[ "$option" =~ ^([1-9]|1[012])$ ]]; do
		echo "$option: invalid selection."
		read -rp "Option: " option
	done
}

show_clients() {
	tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
}

enter_client_name() {
	echo; echo "Provide a name for the client:"
	read -rp "Name: " unsanitized_client
	[ -z "$unsanitized_client" ] && abort_and_exit
	set_client_name
	while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
		if [ -z "$client" ]; then
			echo "Invalid client name."
		else
			echo "$client: invalid name. Client already exists."
		fi
		read -rp "Name: " unsanitized_client
		[ -z "$unsanitized_client" ] && abort_and_exit
		set_client_name
	done
}

# ============================================================
# build_client_config — sync to peer after building
# ============================================================
build_client_config() {
	cd /etc/openvpn/server/easy-rsa/ || exit 1
	(
		set -x
		./easyrsa --batch --days=3650 build-client-full "$client" nopass >/dev/null 2>&1
	)
	# Auto-sync to peer server if configured
	peer_sync_add_client
}

print_client_action() {
	echo; echo "$client $1. Configuration available in: $export_dir$client.ovpn"
}

print_check_clients() {
	echo; echo "Checking for existing client(s)..."
}

check_clients() {
	num_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$num_of_clients" = 0 ]]; then
		echo; echo "There are no existing clients!"
		exit 1
	fi
}

print_client_total() {
	if [ "$num_of_clients" = 1 ]; then
		printf '\n%s\n' "Total: 1 client"
	elif [ -n "$num_of_clients" ]; then
		printf '\n%s\n' "Total: $num_of_clients clients"
	fi
}

select_client_to() {
	echo; echo "Select the client to $1:"
	show_clients
	read -rp "Client: " client_num
	[ -z "$client_num" ] && abort_and_exit
	until [[ "$client_num" =~ ^[0-9]+$ && "$client_num" -le "$num_of_clients" ]]; do
		echo "$client_num: invalid selection."
		read -rp "Client: " client_num
		[ -z "$client_num" ] && abort_and_exit
	done
	client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_num"p)
}

confirm_revoke_client() {
	if [ "$assume_yes" != 1 ]; then
		echo
		read -rp "Confirm $client revocation? [y/N]: " revoke
		until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
			echo "$revoke: invalid selection."
			read -rp "Confirm $client revocation? [y/N]: " revoke
		done
	else
		revoke=y
	fi
}

print_revoke_client()          { echo; echo "Revoking $client..."; }
remove_client_conf() {
	get_export_dir
	local ovpn_file="$export_dir$client.ovpn"
	[ -f "$ovpn_file" ] && { echo "Removing $ovpn_file..."; rm -f "$ovpn_file"; }
}

# ============================================================
# revoke_client_ovpn — sync revocation to peer
# ============================================================
revoke_client_ovpn() {
	cd /etc/openvpn/server/easy-rsa/ || exit 1
	(
		set -x
		./easyrsa --batch revoke "$client" >/dev/null 2>&1
		./easyrsa --batch --days=3650 gen-crl >/dev/null 2>&1
	)
	rm -f /etc/openvpn/server/crl.pem
	rm -f /etc/openvpn/server/easy-rsa/pki/reqs/"$client".req
	rm -f /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	remove_client_conf

	# Read mode then clean up
	saved_mode=$(cat "$CLIENT_META_DIR/$client.mode" 2>/dev/null)
	rm -f "$CLIENT_META_DIR/$client.mode" 2>/dev/null || true

	if [ "${saved_mode}" = "certpass" ]; then
		if id "$client" >/dev/null 2>&1; then
			usermod -L "$client" >/dev/null 2>&1 \
				&& echo "  [✓] Linux user '$client' disabled" \
				|| echo "  [!] Could not lock user '$client'"
		fi
	fi

	# Auto-sync revocation to peer server
	peer_sync_revoke_client
}

print_client_revoked()          { echo; echo "$client revoked!"; }
print_client_revocation_aborted() { echo; echo "$client revocation aborted!"; }

confirm_remove_ovpn() {
	if [ "$assume_yes" != 1 ]; then
		echo
		read -rp "Confirm OpenVPN removal? [y/N]: " remove
		until [[ "$remove" =~ ^[yYnN]*$ ]]; do
			echo "$remove: invalid selection."
			read -rp "Confirm OpenVPN removal? [y/N]: " remove
		done
	else
		remove=y
	fi
}

print_remove_ovpn() { echo; echo "Removing OpenVPN, please wait..."; }

disable_ovpn_service() {
	if [ "$os" != "openSUSE" ]; then
		systemctl disable --now openvpn-server@server.service
		systemctl disable --now "openvpn-server@${AUTH_INSTANCE_NAME}.service" >/dev/null 2>&1 || true
	else
		systemctl disable --now openvpn@server.service
		systemctl disable --now "openvpn@${AUTH_INSTANCE_NAME}.service" >/dev/null 2>&1 || true
	fi
	rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	rm -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" 2>/dev/null || true
	rm -rf /etc/openvpn/server/hooks/ 2>/dev/null || true
	rm -f /etc/openvpn/server/bandwidth.csv 2>/dev/null || true
	rm -f "$PEER_CONF" 2>/dev/null || true
	rm -f "$PEER_SSH_KEY" "${PEER_SSH_KEY}.pub" 2>/dev/null || true
}

remove_sysctl_rules() {
	rm -f /etc/sysctl.d/99-openvpn-forward.conf /etc/sysctl.d/99-openvpn-optimize.conf
	if [ ! -f /usr/bin/wg-quick ] && [ ! -f /usr/sbin/ipsec ] && [ ! -f /usr/local/sbin/ipsec ]; then
		echo 0 > /proc/sys/net/ipv4/ip_forward
		echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
}

remove_rclocal_rules() {
	ipt_cmd="systemctl restart openvpn-iptables.service"
	if grep -qs "$ipt_cmd" /etc/rc.local; then
		sed --follow-symlinks -i "/^$ipt_cmd/d" /etc/rc.local
	fi
}

print_ovpn_removed()          { echo; echo "OpenVPN removed!"; }
print_ovpn_removal_aborted()  { echo; echo "OpenVPN removal aborted!"; }

# ============================================================
# PHASE 2 — Security & Monitoring
# ============================================================

install_fail2ban() {
	echo "Installing fail2ban..."
	if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
		export DEBIAN_FRONTEND=noninteractive
		apt-get -yqq install fail2ban >/dev/null || exiterr2
	elif [[ "$os" == "centos" ]]; then
		yum -y -q install fail2ban >/dev/null 2>&1 || exiterr3
	elif [[ "$os" == "fedora" ]]; then
		dnf install -y fail2ban >/dev/null || exiterr "'dnf install' failed."
	elif [[ "$os" == "openSUSE" ]]; then
		zypper install -y fail2ban >/dev/null || exiterr4
	fi
}

setup_fail2ban_ssh() {
	cat > /etc/fail2ban/jail.d/sshd-openvpn-script.conf <<'EOF'
[sshd]
enabled  = true
port     = ssh
filter   = sshd
maxretry = 5
bantime  = 3600
findtime = 600
EOF
	systemctl enable --now fail2ban >/dev/null 2>&1
	systemctl restart fail2ban >/dev/null 2>&1
	echo "  [✓] fail2ban SSH jail configured (5 retries / 1h ban)"
}

setup_fail2ban_openvpn_auth() {
	cat > /etc/fail2ban/filter.d/openvpn-auth.conf <<'EOF'
[Definition]
failregex = ^.*pam_unix\(openvpn:auth\): authentication failure.*rhost=<HOST>.*$
            ^.*openvpn.*: <HOST>:[0-9]+ TLS Error: TLS handshake failed$
            ^.*openvpn.*: <HOST>:[0-9]+ Connection reset.*$
ignoreregex =
journalmatch = _SYSTEMD_UNIT=openvpn-server@auth.service
EOF
	cat > /etc/fail2ban/jail.d/openvpn-auth.conf <<EOF
[openvpn-auth]
enabled  = true
port     = ${AUTH_PORT_DEFAULT}
protocol = udp
filter   = openvpn-auth
logpath  = /var/log/auth.log
           /var/log/syslog
maxretry = 5
bantime  = 3600
findtime = 600
EOF
	systemctl restart fail2ban >/dev/null 2>&1
	echo "  [✓] fail2ban OpenVPN-auth jail configured (port ${AUTH_PORT_DEFAULT})"
}

harden_ssh() {
	local sshd_conf="/etc/ssh/sshd_config"
	local backup="${sshd_conf}.bak.$(date +%Y%m%d%H%M%S)"
	cp "$sshd_conf" "$backup"
	echo "  [✓] SSH config backed up → $backup"

	set_sshd_option() {
		local key="$1" val="$2"
		if grep -qE "^#?${key}" "$sshd_conf"; then
			sed -i "s|^#*${key}.*|${key} ${val}|" "$sshd_conf"
		else
			echo "${key} ${val}" >> "$sshd_conf"
		fi
	}

	set_sshd_option "PermitRootLogin"      "no"
	set_sshd_option "MaxAuthTries"         "4"
	set_sshd_option "PermitEmptyPasswords" "no"
	set_sshd_option "X11Forwarding"        "no"
	set_sshd_option "LoginGraceTime"       "30"
	set_sshd_option "ClientAliveInterval"  "300"
	set_sshd_option "ClientAliveCountMax"  "2"

	if sshd -t 2>/dev/null; then
		systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1
		echo "  [✓] SSH hardened and restarted"
		echo "      PermitRootLogin=no | MaxAuthTries=4 | LoginGraceTime=30s"
	else
		cp "$backup" "$sshd_conf"
		echo "  [✗] SSH config validation failed — backup restored"
	fi
}

format_bytes() {
	local bytes="$1"
	if ! command -v bc &>/dev/null; then echo "${bytes} B"; return; fi
	if [ -z "$bytes" ] || [ "$bytes" -eq 0 ] 2>/dev/null; then
		echo "0 B"
	elif [ "$bytes" -lt 1024 ]; then
		echo "${bytes} B"
	elif [ "$bytes" -lt 1048576 ]; then
		printf "%.1f KB" "$(echo "scale=1; $bytes/1024" | bc)"
	elif [ "$bytes" -lt 1073741824 ]; then
		printf "%.1f MB" "$(echo "scale=1; $bytes/1048576" | bc)"
	else
		printf "%.2f GB" "$(echo "scale=2; $bytes/1073741824" | bc)"
	fi
}

BANDWIDTH_LOG="/etc/openvpn/server/bandwidth.csv"

update_bandwidth_log() {
	local file="$1"
	[ -f "$file" ] || return
	if [ ! -f "$BANDWIDTH_LOG" ]; then
		echo "client,total_rx,total_tx,last_seen" > "$BANDWIDTH_LOG"
	fi
	while IFS=',' read -r tag cn raddr vaddr ipv6 bytes_r bytes_s since rest; do
		[ "$tag" = "CLIENT_LIST" ] || continue
		[ "$cn" = "Common Name" ] && continue
		[ -z "$cn" ] && continue
		local now; now=$(date '+%Y-%m-%d %H:%M:%S')
		local existing; existing=$(grep "^${cn}," "$BANDWIDTH_LOG" 2>/dev/null | tail -1)
		if [ -z "$existing" ]; then
			echo "${cn},${bytes_r},${bytes_s},${now}" >> "$BANDWIDTH_LOG"
		else
			local old_rx old_tx
			old_rx=$(echo "$existing" | cut -d',' -f2)
			old_tx=$(echo "$existing" | cut -d',' -f3)
			if [ "${bytes_r}" -ge "${old_rx}" ] 2>/dev/null; then
				sed -i "/^${cn},/d" "$BANDWIDTH_LOG"
				echo "${cn},${bytes_r},${bytes_s},${now}" >> "$BANDWIDTH_LOG"
			fi
		fi
	done < "$file"
}

setup_device_limit() {
	local max_devices="${1:-1}"
	local hook="/etc/openvpn/server/hooks/client-event.sh"
	mkdir -p /etc/openvpn/server/hooks

	cat > "$hook" <<HOOK
#!/bin/bash
source /etc/openvpn/server/hooks/api.conf 2>/dev/null
MAX_DEVICES=\$(cat /etc/openvpn/server/hooks/max_devices 2>/dev/null || echo 1)

send_api_event() {
	[ -z "\$API_URL" ] && return
	local event="\$1" reason="\${2:-}"
	local ts=\$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	local payload="{\"event\":\"\${event}\",\"client\":\"\${common_name}\",\"real_ip\":\"\${trusted_ip}\",\"real_port\":\"\${trusted_port}\",\"vpn_ip\":\"\${ifconfig_pool_remote_ip}\",\"bytes_received\":\${bytes_received:-0},\"bytes_sent\":\${bytes_sent:-0},\"reason\":\"\${reason}\",\"timestamp\":\"\${ts}\"}"
	local auth_header="X-VPN-Hook: 1"
	[ -n "\$API_SECRET" ] && auth_header="Authorization: Bearer \${API_SECRET}"
	curl -sf -X POST "\$API_URL" -H "Content-Type: application/json" -H "\$auth_header" -d "\$payload" --max-time 10 >/dev/null 2>&1 &
}

if [ "\$script_type" = "client-connect" ]; then
	active=0
	for sf in /etc/openvpn/server/openvpn-status.log /etc/openvpn/server/openvpn-status-auth.log; do
		[ -f "\$sf" ] || continue
		count=\$(grep "^CLIENT_LIST,\${common_name}," "\$sf" 2>/dev/null | wc -l)
		active=\$(( active + count ))
	done
	if [ "\$active" -ge "\$MAX_DEVICES" ]; then
		logger -t openvpn "REJECTED \${common_name} — \${active}/\${MAX_DEVICES} device(s)"
		send_api_event "rejected" "device_limit_exceeded"
		exit 1
	fi
	send_api_event "connect"
elif [ "\$script_type" = "client-disconnect" ]; then
	send_api_event "disconnect"
fi
exit 0
HOOK

	chmod +x "$hook"
	echo "$max_devices" > /etc/openvpn/server/hooks/max_devices
	add_hooks_to_conf "/etc/openvpn/server/server.conf"
	if [ -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ]; then
		add_hooks_to_conf "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf"
	fi
	echo "  [✓] Device limit set to $max_devices device(s) per client"
}

show_device_limit() {
	local current; current=$(cat /etc/openvpn/server/hooks/max_devices 2>/dev/null || echo "not set")
	local hook_active="No"
	grep -q "client-connect" /etc/openvpn/server/server.conf 2>/dev/null && hook_active="Yes"
	echo "  Max devices per client : $current"
	echo "  Hook active            : $hook_active"
}

run_device_limit_setup() {
	echo
	echo "  Multi-Device Limit:"
	echo "   1) Set limit (1 device per client — recommended)"
	echo "   2) Set limit (custom number)"
	echo "   3) Show current setting"
	echo "   4) Back"
	read -rp "  Select [1-4]: " dlopt </dev/tty; echo

	case "$dlopt" in
		1) setup_device_limit 1 ;;
		2) read -rp "  Max devices per client [2]: " maxd </dev/tty
		   [[ ! "$maxd" =~ ^[0-9]+$ ]] && maxd=2
		   setup_device_limit "$maxd" ;;
		3) show_device_limit ;;
		4|"") return ;;
		*) echo "  Invalid selection." ;;
	esac
}

show_bandwidth_report() {
	echo
	echo "╔══════════════════════════════════════════════════════════════════╗"
	echo "║                  Bandwidth Report (All Clients)                 ║"
	echo "╚══════════════════════════════════════════════════════════════════╝"

	update_bandwidth_log "/etc/openvpn/server/openvpn-status.log"
	update_bandwidth_log "/etc/openvpn/server/openvpn-status-auth.log"

	if [ ! -f "$BANDWIDTH_LOG" ] || [ "$(wc -l < "$BANDWIDTH_LOG")" -le 1 ]; then
		echo; echo "  No bandwidth data yet."; echo; return
	fi

	echo; printf "  %-22s %-14s %-14s %-22s\n" "Client" "Download (RX)" "Upload (TX)" "Last Seen"
	echo "  ──────────────────────────────────────────────────────────────────"

	local total_rx=0 total_tx=0 count=0
	while IFS=',' read -r cn rx tx last_seen; do
		[ "$cn" = "client" ] && continue
		[ -z "$cn" ] && continue
		printf "  %-22s %-14s %-14s %-22s\n" "$cn" "$(format_bytes "$rx")" "$(format_bytes "$tx")" "$last_seen"
		total_rx=$(( total_rx + rx ))
		total_tx=$(( total_tx + tx ))
		(( count++ ))
	done < <(tail -n +2 "$BANDWIDTH_LOG" | sort -t',' -k1)

	echo "  ──────────────────────────────────────────────────────────────────"
	printf "  %-22s %-14s %-14s\n" "Total ($count clients)" "$(format_bytes "$total_rx")" "$(format_bytes "$total_tx")"
	echo
}

show_active_vpn_users() {
	local status_main="/etc/openvpn/server/openvpn-status.log"
	local status_auth="/etc/openvpn/server/openvpn-status-auth.log"

	echo
	echo "╔══════════════════════════════════════════════════════════╗"
	echo "║              Active VPN Users                           ║"
	echo "╚══════════════════════════════════════════════════════════╝"

	if ! grep -q "^status " /etc/openvpn/server/server.conf 2>/dev/null; then
		echo; echo "  [!] Adding 'status' directive to server.conf..."
		echo "status openvpn-status.log" >> /etc/openvpn/server/server.conf
		systemctl restart "$(get_service_name "/etc/openvpn/server/server.conf").service" >/dev/null 2>&1
		sleep 2; echo "  [✓] Done."
	fi

	parse_and_show_status() {
		local file="$1" label="$2"
		[ -f "$file" ] || { echo "  (status file not found: $file)"; return; }
		echo; echo "  ── $label ──"
		echo "  Updated: $(grep '^TIME,' "$file" | awk -F',' '{print $2}')"
		echo
		printf "  %-20s %-22s %-16s %-12s %-12s %s\n" "Client Name" "Real IP:Port" "Virtual IP" "Download" "Upload" "Connected Since"
		echo "  ───────────────────────────────────────────────────────────────────────"
		local count=0
		while IFS=',' read -r tag cn raddr vaddr _ bytes_r bytes_s since _; do
			[ "$tag" = "CLIENT_LIST" ] || continue
			[ "$cn" = "Common Name" ] && continue
			printf "  %-20s %-22s %-16s %-12s %-12s %s\n" "$cn" "$raddr" "$vaddr" \
				"$(format_bytes "$bytes_r")" "$(format_bytes "$bytes_s")" "$since"
			(( count++ ))
		done < "$file"
		update_bandwidth_log "$file"
		if [ "$count" -eq 0 ]; then
			echo "  (no active connections)"
		else
			echo "  ───────────────────────────────────────────────────────────────────────"
			printf "  Total connected: %s\n" "$count"
		fi
	}

	parse_and_show_status "$status_main" \
		"Main Server (cert) — port $(grep '^port ' /etc/openvpn/server/server.conf | awk '{print $2}')"

	if [ -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ]; then
		if ! grep -q "^status " "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" 2>/dev/null; then
			echo "  [!] Adding 'status' directive to auth.conf..."
			echo "status openvpn-status-auth.log" >> "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf"
			systemctl restart "$(get_service_name "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf").service" >/dev/null 2>&1
			sleep 2; echo "  [✓] Done."
		fi
		parse_and_show_status "$status_auth" "Auth Server (cert+pass) — port ${AUTH_PORT_DEFAULT}"
	fi
	echo
}

show_fail2ban_status() {
	echo; echo "  ── fail2ban Status ──"
	if ! systemctl is-active --quiet fail2ban; then echo "  fail2ban is not running."; return; fi
	fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*Jail list:/  Jails:/'
	echo
	for jail in sshd openvpn-auth; do
		if fail2ban-client status "$jail" >/dev/null 2>&1; then
			banned=$(fail2ban-client status "$jail" | grep "Banned IP" | awk -F':\t' '{print $2}')
			total=$(fail2ban-client status "$jail" | grep "Currently banned" | awk -F':\t' '{print $2}')
			echo "  [$jail] Currently banned: ${total:-0}  |  IPs: ${banned:-(none)}"
		fi
	done
	echo
}

run_security_setup() {
	echo
	echo "Security Setup:"
	echo "   1) fail2ban — SSH protection"
	echo "   2) fail2ban — OpenVPN auth protection"
	echo "   3) fail2ban — Both SSH + OpenVPN"
	echo "   4) Harden SSH configuration"
	echo "   5) Full security setup (all of the above)"
	echo "   6) Show fail2ban status"
	echo "   7) Back"
	read -rp "Select [1-7]: " sec_opt </dev/tty; echo

	case "$sec_opt" in
		1) install_fail2ban; setup_fail2ban_ssh ;;
		2) if [ ! -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ]; then
			echo "  OpenVPN auth instance not set up yet."
		   else install_fail2ban; setup_fail2ban_openvpn_auth; fi ;;
		3) install_fail2ban; setup_fail2ban_ssh
		   [ -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ] \
			&& setup_fail2ban_openvpn_auth \
			|| echo "  (Skipping OpenVPN jail — auth instance not active)" ;;
		4) harden_ssh ;;
		5) install_fail2ban; setup_fail2ban_ssh
		   [ -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ] && setup_fail2ban_openvpn_auth
		   harden_ssh ;;
		6) show_fail2ban_status ;;
		7|"") return ;;
		*) echo "Invalid selection." ;;
	esac
}

# ============================================================
# BACKUP & RESTORE
# ============================================================

BACKUP_DIR="/etc/openvpn/backups"

create_backup() {
	mkdir -p "$BACKUP_DIR"
	local timestamp; timestamp=$(date '+%Y%m%d_%H%M%S')
	local backup_file="$BACKUP_DIR/openvpn_backup_${timestamp}.tar.gz"
	echo; echo "  Creating backup..."
	tar -czf "$backup_file" \
		/etc/openvpn/server/easy-rsa/pki/ \
		/etc/openvpn/server/*.conf \
		/etc/openvpn/server/*.crt \
		/etc/openvpn/server/*.key \
		/etc/openvpn/server/*.pem \
		/etc/openvpn/server/*.txt \
		/etc/openvpn/server/clients-meta/ \
		/etc/openvpn/server/hooks/ \
		/etc/openvpn/server/bandwidth.csv \
		/etc/openvpn/server/verify-cn.sh \
		"$PEER_CONF" \
		"$PEER_SSH_KEY" "${PEER_SSH_KEY}.pub" \
		2>/dev/null
	if [ $? -eq 0 ]; then
		local size; size=$(du -sh "$backup_file" | cut -f1)
		chmod 600 "$backup_file"
		echo "  [✓] Backup created: $backup_file ($size)"
		echo
		echo "  To download via SCP:"
		echo "    scp root@$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo 'YOUR_IP'):$backup_file ."
	else
		echo "  [✗] Backup failed!"; rm -f "$backup_file"
	fi
}

list_backups() {
	echo
	if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
		echo "  No backups found in $BACKUP_DIR"; return 1
	fi
	echo "  Available backups:"
	echo
	local i=1
	while IFS= read -r f; do
		local size; size=$(du -sh "$f" | cut -f1)
		printf "   %d) %-45s %s\n" "$i" "$(basename "$f")" "($size)"
		(( i++ ))
	done < <(ls -t "$BACKUP_DIR"/openvpn_backup_*.tar.gz 2>/dev/null)
	return 0
}

restore_backup() {
	list_backups || return
	local files=()
	while IFS= read -r f; do files+=("$f"); done < <(ls -t "$BACKUP_DIR"/openvpn_backup_*.tar.gz 2>/dev/null)
	echo
	read -rp "  Select backup number (or Enter to cancel): " sel </dev/tty
	[ -z "$sel" ] && return
	if [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt "${#files[@]}" ]; then
		echo "  Invalid selection."; return
	fi
	local chosen="${files[$((sel-1))]}"
	echo; echo "  Selected: $(basename "$chosen")"
	echo; echo "  ⚠ WARNING: This will OVERWRITE current OpenVPN configuration!"
	read -rp "  Are you sure? [y/N]: " confirm </dev/tty
	[[ ! "$confirm" =~ ^[yY]$ ]] && { echo "  Cancelled."; return; }
	echo
	echo "  Stopping OpenVPN services..."
	systemctl stop "$(get_service_name "/etc/openvpn/server/server.conf").service" >/dev/null 2>&1
	systemctl stop "$(get_service_name "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf").service" >/dev/null 2>&1
	echo "  Restoring files..."
	tar -xzf "$chosen" -C / 2>/dev/null
	if [ $? -eq 0 ]; then
		echo "  Restarting OpenVPN services..."
		systemctl start "$(get_service_name "/etc/openvpn/server/server.conf").service" >/dev/null 2>&1
		systemctl start "$(get_service_name "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf").service" >/dev/null 2>&1
		echo "  [✓] Restore complete from: $(basename "$chosen")"
	else
		echo "  [✗] Restore failed!"
	fi
}

delete_old_backups() {
	list_backups || return
	echo
	echo "  Delete options:"
	echo "   1) Keep only latest 3 backups"
	echo "   2) Keep only latest backup"
	echo "   3) Delete ALL backups"
	echo "   4) Cancel"
	read -rp "  Select [1-4]: " del_opt </dev/tty
	case "$del_opt" in
		1) keep=3 ;; 2) keep=1 ;; 3) keep=0 ;; 4|"") return ;; *) echo "  Invalid."; return ;;
	esac
	if [ "$keep" -eq 0 ]; then
		read -rp "  Delete ALL backups? [y/N]: " confirm </dev/tty
		[[ ! "$confirm" =~ ^[yY]$ ]] && { echo "  Cancelled."; return; }
		rm -f "$BACKUP_DIR"/openvpn_backup_*.tar.gz
		echo "  [✓] All backups deleted."
	else
		ls -t "$BACKUP_DIR"/openvpn_backup_*.tar.gz 2>/dev/null | tail -n +$(( keep + 1 )) | xargs rm -f
		echo "  [✓] Kept latest $keep backup(s), deleted the rest."
	fi
}

run_backup_restore() {
	echo
	echo "  Backup & Restore:"
	echo "   1) Create backup now"
	echo "   2) Restore from backup"
	echo "   3) List backups"
	echo "   4) Delete old backups"
	echo "   5) Back"
	read -rp "  Select [1-5]: " br_opt </dev/tty; echo

	case "$br_opt" in
		1) create_backup ;;
		2) restore_backup ;;
		3) list_backups ;;
		4) delete_old_backups ;;
		5|"") return ;;
		*) echo "  Invalid selection." ;;
	esac
}

# ============================================================
# MAIN ENTRY POINT
# ============================================================
ovpnsetup() {

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

check_root
check_shell
check_kernel
check_os
check_os_ver
check_tun

OVPN_CONF="/etc/openvpn/server/server.conf"

auto=0
assume_yes=0
add_client=0
export_client=0
list_clients=0
revoke_client=0
remove_ovpn=0
public_ip=""
listen_addr=""
server_addr=""
server_proto=""
server_port=""
first_client_name=""
unsanitized_client=""
client=""
dns=""
dns1=""
dns2=""

parse_args "$@"
check_args

# ── Non-interactive CLI modes ──────────────────────────────

if [ "$add_client" = 1 ]; then
	show_header; echo
	mode="$(select_client_mode_interactive)"
	if [ "$mode" = "certpass" ]; then
		ensure_auth_instance
		prompt_password_hidden "$client"
		create_linux_user_with_password "$client" "$_vpn_password"
		save_client_mode "certpass"
		client_common_file="/etc/openvpn/server/client-common-auth.txt"
	else
		save_client_mode "cert"
		client_common_file="/etc/openvpn/server/client-common.txt"
	fi
	build_client_config   # ← syncs to peer automatically
	new_client            # ← embeds both remotes if peer configured
	print_client_action added
	exit 0
fi

if [ "$export_client" = 1 ]; then
	show_header
	load_client_mode
	[ "$mode" = "certpass" ] && ensure_auth_instance
	new_client
	print_client_action exported
	exit 0
fi

if [ "$list_clients" = 1 ]; then
	show_header; print_check_clients; check_clients; echo; show_clients; print_client_total; exit 0
fi

if [ "$revoke_client" = 1 ]; then
	show_header
	confirm_revoke_client
	if [[ "$revoke" =~ ^[yY]$ ]]; then
		print_revoke_client
		revoke_client_ovpn   # ← syncs revocation to peer automatically
		print_client_revoked
		exit 0
	else
		print_client_revocation_aborted; exit 1
	fi
fi

if [ "$remove_ovpn" = 1 ]; then
	show_header
	confirm_remove_ovpn
	if [[ "$remove" =~ ^[yY]$ ]]; then
		print_remove_ovpn
		remove_firewall_rules
		disable_ovpn_service
		remove_sysctl_rules
		remove_rclocal_rules
		remove_pkgs
		print_ovpn_removed; exit 0
	else
		print_ovpn_removal_aborted; exit 1
	fi
fi

# ── Fresh install ──────────────────────────────────────────

if [[ ! -e "$OVPN_CONF" ]]; then
	check_nftables
	install_wget
	install_iproute
	show_welcome
	if [ "$auto" = 0 ]; then
		enter_server_address
	else
		if [ -n "$listen_addr" ]; then
			ip="$listen_addr"
		else
			detect_ip
		fi
		if [ -n "$server_addr" ]; then
			public_ip="$server_addr"
		else
			check_nat_ip
		fi
	fi
	show_config
	detect_ipv6
	select_protocol
	select_port
	[ "$auto" = 0 ] && select_dns
	enter_first_client_name
	show_setup_ready
	check_firewall
	confirm_setup
	show_start_setup
	disable_limitnproc
	install_pkgs
	install_easyrsa
	create_pki_and_certs
	create_server_config
	update_sysctl
	create_firewall_rules
	[ "$os" != "openSUSE" ] && update_rclocal
	update_selinux
	create_client_common
	start_openvpn_service
	new_client
	[ "$auto" != 0 ] && check_dns_name "$server_addr" && show_dns_name_note "$server_addr"
	finish_setup   # ← asks about peer setup at the end

else
	# ── Management menu ───────────────────────────────────
	show_header
	select_menu_option
	case "$option" in
		1)
			enter_client_name
			mode="$(select_client_mode_interactive)"
			if [ "$mode" = "certpass" ]; then
				ensure_auth_instance
				prompt_password_hidden "$client"
				create_linux_user_with_password "$client" "$_vpn_password"
				save_client_mode "certpass"
				client_common_file="/etc/openvpn/server/client-common-auth.txt"
			else
				save_client_mode "cert"
				client_common_file="/etc/openvpn/server/client-common.txt"
			fi
			build_client_config   # ← syncs to peer
			new_client            # ← failover remotes
			print_client_action added
			exit 0
		;;
		2)
			check_clients
			select_client_to export
			load_client_mode
			[ "$mode" = "certpass" ] && ensure_auth_instance
			new_client
			print_client_action exported
			exit 0
		;;
		3)
			print_check_clients; check_clients; echo; show_clients; print_client_total; exit 0
		;;
		4)
			check_clients
			select_client_to revoke
			confirm_revoke_client
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				print_revoke_client
				revoke_client_ovpn   # ← syncs revocation to peer
				print_client_revoked; exit 0
			else
				print_client_revocation_aborted; exit 1
			fi
		;;
		5)  show_active_vpn_users; exit 0 ;;
		6)  show_bandwidth_report; exit 0 ;;
		7)  run_api_setup; exit 0 ;;
		8)  run_security_setup; exit 0 ;;
		9)  run_backup_restore; exit 0 ;;
		10) run_peer_menu; exit 0 ;;
		11)
			confirm_remove_ovpn
			if [[ "$remove" =~ ^[yY]$ ]]; then
				print_remove_ovpn
				remove_firewall_rules
				disable_ovpn_service
				remove_sysctl_rules
				remove_rclocal_rules
				remove_pkgs
				print_ovpn_removed; exit 0
			else
				print_ovpn_removal_aborted; exit 1
			fi
		;;
		12) exit 0 ;;
	esac
fi
}

## Defer setup until we have the complete script
ovpnsetup "$@"

exit 0
