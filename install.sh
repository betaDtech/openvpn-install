#!/bin/bash
#
# https://github.com/betaDtech/openvpn-install
#
# Based on the work of Nyr and contributors at:
# https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2022-2026 betaDtech <ahmedmansour08@gmail.com>
# Copyright (c) 2013-2023 Nyr
#
# Released under the MIT License, see the accompanying file LICENSE.txt
# or https://opensource.org/licenses/MIT
umask 077
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
	# Detect Debian users running the script with "sh" instead of bash
	if readlink /proc/$$/exe | grep -q "dash"; then
		exiterr 'This installer needs to be run with "bash", not "sh".'
	fi
}

check_kernel() {
	# Detect OpenVZ 6
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
		exiterr "Ubuntu 20.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	fi
	if [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
		exiterr "Debian 10 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	fi
	if [[ "$os" == "centos" && "$os_version" -lt 8 ]]; then
		if ! grep -qs "Amazon Linux release 2 " /etc/system-release; then
			exiterr "CentOS 8 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
		fi
	fi
}

check_tun() {
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		exiterr "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	fi
}

set_client_name() {
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
}

# ---- Multi-mode client support (cert-only vs user/pass + cert) ----
CLIENT_META_DIR="/etc/openvpn/server/clients-meta"
AUTH_INSTANCE_NAME="auth"
AUTH_PORT_DEFAULT="8443"
AUTH_VPN_NET="172.16.254.0"
AUTH_VPN_MASK="255.255.255.0"
AUTH_VPN_CIDR="172.16.254.0/24"
PAM_SERVICE_NAME="openvpn"
PAM_PLUGIN_PATH=""

# ---- API Webhook ----
VPN_API_URL=""
VPN_API_SECRET=""
VPN_HOOK_SCRIPT="/etc/openvpn/server/hooks/client-event.sh"

setup_api_webhook() {
	echo
	read -rp "  Enter API URL (e.g. https://abc.xyz/api/vpn): " api_url </dev/tty
	[ -z "$api_url" ] && { echo "  Cancelled."; return; }
	case "$api_url" in
		http://*|https://*) ;;
		*)
			echo "  Invalid API URL. Must start with http:// or https://"
			return
			;;
	esac
	if printf '%s' "$api_url" | grep -q '[[:space:]]'; then
		echo "  Invalid API URL. Spaces are not allowed."
		return
	fi
	read -rsp "  Enter API Secret (Bearer token, or press Enter to skip): " api_secret </dev/tty
	echo

	# Save the settings
	mkdir -p /etc/openvpn/server/hooks
	cat > /etc/openvpn/server/hooks/api.conf <<EOF
API_URL="${api_url}"
API_SECRET="${api_secret}"
EOF
	chmod 600 /etc/openvpn/server/hooks/api.conf

	# Create the hook script
	if [ ! -f "$VPN_HOOK_SCRIPT" ]; then
		echo "  [!] Hook script not found."
		echo "      Go to: API & Automation → Multi-device limit setup → option 1"
		echo "      This will create the hook with both API + device limit."
		return
	fi

	# Add the hooks to server.conf
	add_hooks_to_conf "/etc/openvpn/server/server.conf"

	# Add to auth.conf if it exists
	if [ -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ]; then
		add_hooks_to_conf "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf"
	fi

	echo "  [✓] Webhook configured → $api_url"
	echo "  [✓] Hook script created → $VPN_HOOK_SCRIPT"
	echo
	echo "  Payload on connect/disconnect:"
	echo '  {'
	echo '    "event": "connect" | "disconnect",'
	echo '    "client": "client_name",'
	echo '    "real_ip": "x.x.x.x",'
	echo '    "real_port": 12345,'
	echo '    "vpn_ip": "172.16.x.x",'
	echo '    "bytes_received": 1234,'
	echo '    "bytes_sent": 5678,'
	echo '    "timestamp": "2026-03-06T19:00:00Z"'
	echo '  }'
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
	local sec_level="2"
	local restart_needed=0
	local current_sec=""

	[ -f "$conf" ] || return 0
	[ "$(basename "$conf")" = "${AUTH_INSTANCE_NAME}.conf" ] && sec_level="3"

	if grep -q '^script-security ' "$conf" 2>/dev/null; then
		current_sec="$(awk '/^script-security /{print $2; exit}' "$conf")"
		if [ "$current_sec" != "$sec_level" ]; then
			sed -i "s/^script-security .*/script-security ${sec_level}/" "$conf"
			restart_needed=1
		fi
	else
		echo "script-security ${sec_level}" >> "$conf"
		restart_needed=1
	fi

	if ! grep -q '^client-connect ' "$conf" 2>/dev/null; then
		echo "client-connect ${VPN_HOOK_SCRIPT}" >> "$conf"
		echo "client-disconnect ${VPN_HOOK_SCRIPT}" >> "$conf"
		restart_needed=1
	fi

	if [ "$restart_needed" -eq 1 ]; then
		systemctl restart "$(get_service_name "$conf").service" >/dev/null 2>&1
		echo "  [✓] Hooks/script-security updated in $(basename "$conf") and service restarted"
	else
		echo "  [i] Hooks already present in $(basename "$conf")"
	fi
}

test_api_webhook() {
	[ -f /etc/openvpn/server/hooks/api.conf ] || { echo "  No API configured yet."; return; }
	source /etc/openvpn/server/hooks/api.conf

	echo "  Testing webhook → $API_URL"

	PAYLOAD='{"event":"test","client":"test-client","real_ip":"1.2.3.4","real_port":12345,"vpn_ip":"172.16.255.2","bytes_received":0,"bytes_sent":0,"timestamp":"'$(date -u '+%Y-%m-%dT%H:%M:%SZ')'"}'

	if [ -n "$API_SECRET" ]; then
		AUTH_HEADER="Authorization: Bearer ${API_SECRET}"
	else
		AUTH_HEADER="X-VPN-Hook: 1"
	fi

	response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_URL" \
		-H "Content-Type: application/json" \
		-H "$AUTH_HEADER" \
		-d "$PAYLOAD" \
		--max-time 10)

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
		cert)
			client_common_file="/etc/openvpn/server/client-common.txt"
			;;
		certpass)
			client_common_file="/etc/openvpn/server/client-common-auth.txt"
			;;
		*)
			mode="cert"
			client_common_file="/etc/openvpn/server/client-common.txt"
			;;
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
		1|"") echo "cert" ;;
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
		[ "$p1" = "$p2" ] || { echo "Passwords do not match. Try again." >/dev/tty; continue; }
		_vpn_password="$p1"
		return 0
	done
}

create_linux_user_with_password() {
	local u="$1" p="$2"

	# Safety guard: never touch root/system accounts
	if [ "$u" = "root" ]; then
		exiterr "Refusing to use username 'root' for VPN clients."
	fi
	# Do not modify any existing system user
	if id "$u" >/dev/null 2>&1; then
		exiterr "User '$u' already exists on the system. Choose a different VPN client name."
	fi

	nologin_path=$(command -v nologin 2>/dev/null \
		|| { for p in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin; do
			[ -x "$p" ] && echo "$p" && break
		done; })
	[ -z "$nologin_path" ] && exiterr "Cannot find nologin binary"

	useradd -m -s "$nologin_path" "$u" || exiterr "Failed to create user $u"
	printf '%s:%s\n' "$u" "$p" | chpasswd || exiterr "Failed to set password for $u"
}

create_pam_config() {
	if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
		if [ ! -f "/etc/pam.d/${PAM_SERVICE_NAME}" ]; then
			cat > "/etc/pam.d/${PAM_SERVICE_NAME}" <<'EOF'
# PAM config for OpenVPN (username/password)
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
	[ -n "$server_proto" ] && [ -n "$server_ip" ] && [ -n "$server_port" ] || exiterr "Could not detect proto/ip/port from $cc"
}

make_client_common_auth() {
	read_current_proto_ip_port
	local out="/etc/openvpn/server/client-common-auth.txt"

	# copy existing template and change remote port
	sed -E "s/^remote[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+$/remote $server_ip $AUTH_PORT_DEFAULT/" \
		/etc/openvpn/server/client-common.txt > "$out"

	# ensure auth-user-pass is present
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

	detect_pam_plugin || exiterr "PAM plugin not found. Install OpenVPN package that includes auth-pam plugin."

	read_current_proto_ip_port

	# ---- FIX #1: Correct path for verify-cn.sh ----
	cat > /etc/openvpn/server/verify-cn.sh <<'EOF'
#!/bin/bash
# OpenVPN calls this with username in $username env var
# common_name is also available as env var
if [ -z "$username" ] || [ -z "$common_name" ]; then
	exit 1
fi
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
#cipher AES-128-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-128-GCM
tls-version-min 1.2
# REQUIRE BOTH: cert + username/password (PAM)
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
	# ---- END FIX #1 + FIX #3 ----

	create_firewall_rules_auth
	systemctl enable --now "$(get_service_name "$conf").service" >/dev/null 2>&1
}
# ---- end multi-mode ----


parse_args() {
	while [ "$#" -gt 0 ]; do
		case $1 in
			--auto)
				auto=1
				shift
				;;
			--addclient)
				add_client=1
				unsanitized_client="$2"
				shift
				shift
				;;
			--exportclient)
				export_client=1
				unsanitized_client="$2"
				shift
				shift
				;;
			--listclients)
				list_clients=1
				shift
				;;
			--revokeclient)
				revoke_client=1
				unsanitized_client="$2"
				shift
				shift
				;;
			--uninstall)
				remove_ovpn=1
				shift
				;;
			--listenaddr)
				listen_addr="$2"
				shift
				shift
				;;
			--serveraddr)
				server_addr="$2"
				shift
				shift
				;;
			--proto)
				server_proto="$2"
				shift
				shift
				;;
			--port)
				server_port="$2"
				shift
				shift
				;;
			--clientname)
				first_client_name="$2"
				shift
				shift
				;;
			--dns1)
				dns1="$2"
				shift
				shift
				;;
			--dns2)
				dns2="$2"
				shift
				shift
				;;
			-y|--yes)
				assume_yes=1
				shift
				;;
			-h|--help)
				show_usage
				;;
			*)
				show_usage "Unknown parameter: $1"
				;;
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
		[ "$add_client" = 1 ] && exiterr "$st_text adding a client."
		[ "$export_client" = 1 ] && exiterr "$st_text exporting a client."
		[ "$list_clients" = 1 ] && exiterr "$st_text listing clients."
		[ "$revoke_client" = 1 ] && exiterr "$st_text revoking a client."
		[ "$remove_ovpn" = 1 ] && exiterr "Cannot remove OpenVPN because it has not been set up on this server."
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
			exiterr "Invalid client name. Use one word only, no special characters except '-' and '_'."
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
		show_usage "Invalid listen address. Must be an IPv4 address."
	fi
	if [ -n "$listen_addr" ] && [ -z "$server_addr" ]; then
		show_usage "You must also specify the server address if the listen address is specified."
	fi
	if [ -n "$server_addr" ] && { ! check_dns_name "$server_addr" && ! check_ip "$server_addr"; }; then
		exiterr "Invalid server address. Must be a fully qualified domain name (FQDN) or an IPv4 address."
	fi
	if [ -n "$first_client_name" ]; then
		unsanitized_client="$first_client_name"
		set_client_name
		if [ -z "$client" ]; then
			exiterr "Invalid client name. Use one word only, no special characters except '-' and '_'."
		fi
	fi
	if [ -n "$server_proto" ]; then
		case "$server_proto" in
			[tT][cC][pP])
				server_proto=tcp
				;;
			[uU][dD][pP])
				server_proto=udp
				;;
			*)
				exiterr "Invalid protocol. Must be TCP or UDP."
				;;
		esac
	fi
	if [ -n "$server_port" ]; then
		if [[ ! "$server_port" =~ ^[0-9]+$ || "$server_port" -gt 65535 ]]; then
			exiterr "Invalid port. Must be an integer between 1 and 65535."
		fi
	fi
	if { [ -n "$dns1" ] && ! check_ip "$dns1"; } \
		|| { [ -n "$dns2" ] && ! check_ip "$dns2"; }; then
		exiterr "Invalid DNS server(s)."
	fi
	if [ -z "$dns1" ] && [ -n "$dns2" ]; then
		show_usage "Invalid DNS server. --dns2 cannot be specified without --dns1."
	fi
	if [ -n "$dns1" ]; then
		dns=7
	else
		dns=2
	fi
}

check_nftables() {
	if [ "$os" = "centos" ]; then
		if grep -qs "hwdsl2 VPN script" /etc/sysconfig/nftables.conf \
			|| systemctl is-active --quiet nftables 2>/dev/null; then
			exiterr "This system has nftables enabled, which is not supported by this installer."
		fi
	fi
}

install_wget() {
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "Wget is required to use this installer."
			read -n1 -r -p "Press any key to install Wget and continue..."
		fi
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install wget >/dev/null
		) || exiterr2
	fi
}

install_iproute() {
	if ! hash ip 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "iproute is required to use this installer."
			read -n1 -r -p "Press any key to install iproute and continue..."
		fi
		if [ "$os" = "debian" ] || [ "$os" = "ubuntu" ]; then
			export DEBIAN_FRONTEND=noninteractive
			(
				set -x
				apt-get -yqq update || apt-get -yqq update
				apt-get -yqq install iproute2 >/dev/null
			) || exiterr2
		elif [ "$os" = "openSUSE" ]; then
			(
				set -x
				zypper install iproute2 >/dev/null
			) || exiterr4
		else
			(
				set -x
				yum -y -q install iproute >/dev/null
			) || exiterr3
		fi
	fi
}

show_header() {
cat <<'EOF'

OpenVPN Script
https://github.com/betaDtech/openvpn-install
EOF
}

show_header2() {
cat <<'EOF'

Welcome to this OpenVPN server installer!
GitHub: https://github.com/betaDtech/openvpn-install

EOF
}

show_header3() {
cat <<'EOF'

Copyright (c) 2022-2026 Ahmed Magdy
Copyright (c) 2013-2023 Nyr
EOF
}

show_usage() {
	if [ -n "$1" ]; then
		echo "Error: $1" >&2
	fi
	show_header
	show_header3
cat 1>&2 <<EOF

Usage: bash $0 [options]

Options:

  --addclient [client name]      add a new client (prompts for auth mode)
  --exportclient [client name]   export configuration for an existing client
  --listclients                  list the names of existing clients
  --revokeclient [client name]   revoke an existing client
  --uninstall                    remove OpenVPN and delete all configuration
  -y, --yes                      assume "yes" as answer to prompts when revoking a client or removing OpenVPN
  -h, --help                     show this help message and exit

Install options (optional):

  --auto                         auto install OpenVPN using default or custom options
  --listenaddr [IPv4 address]    IPv4 address that OpenVPN should listen on for requests
  --serveraddr [DNS name or IP]  server address, must be a fully qualified domain name (FQDN) or an IPv4 address
  --proto [TCP or UDP]           protocol for OpenVPN (TCP or UDP, default: UDP)
  --port [number]                port for OpenVPN (1-65535, default: 1194)
  --clientname [client name]     name for the first OpenVPN client (default: client)
  --dns1 [DNS server IP]         primary DNS server for clients (default: Google Public DNS)
  --dns2 [DNS server IP]         secondary DNS server for clients

To customize options, you may also run this script without arguments.
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
			use_dns_name=1
			echo
			;;
		*)
			use_dns_name=0
			;;
	esac
	if [ "$use_dns_name" = 1 ]; then
		read -rp "Enter the DNS name of this VPN server: " server_addr_i
		until check_dns_name "$server_addr_i"; do
			echo "Invalid DNS name. You must enter a fully qualified domain name (FQDN)."
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
	# Get public IP and sanitize with grep
	get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "$ip_url1" || curl -m 10 -4Ls "$ip_url1")")
	if ! check_ip "$get_public_ip"; then
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "$ip_url2" || curl -m 10 -4Ls "$ip_url2")")
	fi
}

detect_ip() {
	# If system has a single IPv4, it is selected automatically.
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		# Use the IP address on the default route
		ip=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}' 2>/dev/null)
		if ! check_ip "$ip"; then
			find_public_ip
			ip_match=0
			if [ -n "$get_public_ip" ]; then
				ip_list=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
				while IFS= read -r line; do
					if [ "$line" = "$get_public_ip" ]; then
						ip_match=1
						ip="$line"
					fi
				done <<< "$ip_list"
			fi
			if [ "$ip_match" = 0 ]; then
				if [ "$auto" = 0 ]; then
					echo
					echo "Which IPv4 address should be used?"
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
	# If $ip is a private IP address, the server must be behind NAT
	if check_pvt_ip "$ip"; then
		find_public_ip
		if ! check_ip "$get_public_ip"; then
			if [ "$auto" = 0 ]; then
				echo
				echo "This server is behind NAT. What is the public IPv4 address?"
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
		if [ -n "$listen_addr" ]; then
			echo "Listen address: $listen_addr"
		fi
		if [ -n "$server_addr" ]; then
			echo "Server address: $server_addr"
		else
			printf '%s' "Server IP: "
			[ -n "$public_ip" ] && printf '%s\n' "$public_ip" || printf '%s\n' "$ip"
		fi
		if [ "$server_proto" = "tcp" ]; then
			proto_text=TCP
		else
			proto_text=UDP
		fi
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
			1|"")
			protocol=udp
			;;
			2)
			protocol=tcp
			;;
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
	if [ "$dns" = 7 ]; then
		enter_custom_dns
	fi
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
		echo
		echo "OpenVPN installation is ready to begin."
	fi
}

check_firewall() {
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
		elif [[ "$os" == "openSUSE" ]]; then
			firewall="firewalld"
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			firewall="iptables"
		fi
		if [[ "$firewall" == "firewalld" ]]; then
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo
			echo "Note: firewalld, which is required to manage routing tables, will also be installed."
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
			[yY][eE][sS]|[yY]|'')
				:
				;;
			*)
				abort_and_exit
				;;
		esac
	fi
}

show_start_setup() {
	echo
	echo "Installing OpenVPN, please wait..."
}

disable_limitnproc() {
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
}

install_pkgs() {
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq --no-install-recommends install openvpn libpam0g>/dev/null
		) || exiterr2
		(
			set -x
			apt-get -yqq install openssl ca-certificates curl bc $firewall >/dev/null
		) || exiterr2
	elif [[ "$os" = "centos" ]]; then
		if grep -qs "Amazon Linux release 2 " /etc/system-release; then
			(
				set -x
				amazon-linux-extras install epel -y >/dev/null
			) || exit 1
		else
			(
				set -x
				yum -y -q install epel-release >/dev/null
			) || exiterr3
		fi
		(
			set -x
			yum -y -q install openvpn openssl ca-certificates tar curl bc $firewall >/dev/null 2>&1
		) || exiterr3
	elif [[ "$os" = "fedora" ]]; then
		(
			set -x
			dnf install -y openvpn openssl ca-certificates tar curl bc $firewall >/dev/null
		) || exiterr "'dnf install' failed."
	else
		# Else, OS must be openSUSE
		(
			set -x
			zypper install -y openvpn openssl ca-certificates tar curl bc $firewall >/dev/null
		) || exiterr4
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		(
			set -x
			systemctl enable --now firewalld.service >/dev/null 2>&1
		)
	fi
}

remove_pkgs() {
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		(
			set -x
			rm -rf /etc/openvpn/server
			apt-get remove --purge -y openvpn >/dev/null
		)
	elif [[ "$os" = "openSUSE" ]]; then
		(
			set -x
			zypper remove -y openvpn >/dev/null
			rm -rf /etc/openvpn/server
		)
		rm -f /etc/openvpn/ipp.txt
	else
		# Else, OS must be CentOS or Fedora
		(
			set -x
			yum -y -q remove openvpn >/dev/null
			rm -rf /etc/openvpn/server
		)
	fi
}

create_firewall_rules() {
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd -q --add-port="$port"/"$protocol"
		firewall-cmd -q --zone=trusted --add-source=172.16.255.0/24
		firewall-cmd -q --permanent --add-port="$port"/"$protocol"
		firewall-cmd -q --permanent --zone=trusted --add-source=172.16.255.0/24
		# Set NAT for the VPN subnet
		firewall-cmd -q --direct --add-rule ipv4 nat POSTROUTING 0 -s 172.16.255.0/24 ! -d 172.16.255.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 172.16.255.0/24 ! -d 172.16.255.0/24 -j MASQUERADE
		if [[ -n "$ip6" ]]; then
			firewall-cmd -q --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd -q --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd -q --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j MASQUERADE
			firewall-cmd -q --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j MASQUERADE
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
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
		(
			set -x
			systemctl enable --now openvpn-iptables.service >/dev/null 2>&1
		)
	fi
}

remove_firewall_rules() {
	port=$(grep '^port ' "$OVPN_CONF" | cut -d " " -f 2)
	protocol=$(grep '^proto ' "$OVPN_CONF" | cut -d " " -f 2)
	if systemctl is-active --quiet firewalld.service; then
		ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 172.16.255.0/24 '"'"'!'"'"' -d 172.16.255.0/24' | grep -oE '[^ ]+$')
		# Using both permanent and not permanent rules to avoid a firewalld reload.
		firewall-cmd -q --remove-port="$port"/"$protocol"
		firewall-cmd -q --zone=trusted --remove-source=172.16.255.0/24
		firewall-cmd -q --permanent --remove-port="$port"/"$protocol"
		firewall-cmd -q --permanent --zone=trusted --remove-source=172.16.255.0/24
		firewall-cmd -q --direct --remove-rule ipv4 nat POSTROUTING 0 -s 172.16.255.0/24 ! -d 172.16.255.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 172.16.255.0/24 ! -d 172.16.255.0/24 -j MASQUERADE
		if grep -qs "server-ipv6" "$OVPN_CONF"; then
			ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
			firewall-cmd -q --zone=trusted --remove-source=fddd:1194:1194:1194::/64
			firewall-cmd -q --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
			firewall-cmd -q --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j MASQUERADE
			firewall-cmd -q --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j MASQUERADE
		fi
	else
		systemctl disable --now openvpn-iptables.service
		rm -f /etc/systemd/system/openvpn-iptables.service
	fi
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		semanage port -d -t openvpn_port_t -p "$protocol" "$port"
	fi
	# ---- FIX #2 (part A): cleanup auth firewall service ----
	if systemctl is-active --quiet firewalld.service; then
		firewall-cmd -q --remove-port="${AUTH_PORT_DEFAULT}/${protocol}" 2>/dev/null
		firewall-cmd -q --permanent --remove-port="${AUTH_PORT_DEFAULT}/${protocol}" 2>/dev/null
		firewall-cmd -q --zone=trusted --remove-source="$AUTH_VPN_CIDR" 2>/dev/null
		firewall-cmd -q --permanent --zone=trusted --remove-source="$AUTH_VPN_CIDR" 2>/dev/null
		firewall-cmd -q --direct --remove-rule ipv4 nat POSTROUTING 0 \
			-s "$AUTH_VPN_CIDR" ! -d "$AUTH_VPN_CIDR" -j MASQUERADE 2>/dev/null
		firewall-cmd -q --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 \
			-s "$AUTH_VPN_CIDR" ! -d "$AUTH_VPN_CIDR" -j MASQUERADE 2>/dev/null
	else
		systemctl disable --now openvpn-iptables-auth.service >/dev/null 2>&1 || true
		rm -f /etc/systemd/system/openvpn-iptables-auth.service
		systemctl daemon-reload >/dev/null 2>&1
	fi
	# ---- END FIX #2 (part A) ----
}

install_easyrsa() {
	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.5/EasyRSA-3.2.5.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -t 3 -T 30 -qO- "$easy_rsa_url" 2>/dev/null || curl -m 30 -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1 2>/dev/null
	if [ ! -f /etc/openvpn/server/easy-rsa/easyrsa ]; then
		exiterr "Failed to download EasyRSA from $easy_rsa_url."
	fi
	chown -R root:root /etc/openvpn/server/easy-rsa/
}

create_pki_and_certs() {
	cd /etc/openvpn/server/easy-rsa/ || exit 1
	(
		set -x
		# Create the PKI, set up the CA and the server and client certificates
		./easyrsa --batch init-pki >/dev/null
		./easyrsa --batch build-ca nopass >/dev/null 2>&1
		./easyrsa --batch --days=3650 build-server-full server nopass >/dev/null 2>&1
		./easyrsa --batch --days=3650 build-client-full "$client" nopass >/dev/null 2>&1
		./easyrsa --batch --days=3650 gen-crl >/dev/null 2>&1
	)
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	(
		set -x
		# Generate key for tls-crypt
		openvpn --genkey --secret /etc/openvpn/server/tc.key >/dev/null
	)
	# Create the DH parameters file using the predefined ffdhe2048 group
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
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> "$OVPN_CONF"
			done
		;;
		2|"")
			echo 'push "dhcp-option DNS 8.8.8.8"' >> "$OVPN_CONF"
			echo 'push "dhcp-option DNS 8.8.4.4"' >> "$OVPN_CONF"
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> "$OVPN_CONF"
			echo 'push "dhcp-option DNS 1.0.0.1"' >> "$OVPN_CONF"
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> "$OVPN_CONF"
			echo 'push "dhcp-option DNS 208.67.220.220"' >> "$OVPN_CONF"
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> "$OVPN_CONF"
			echo 'push "dhcp-option DNS 149.112.112.112"' >> "$OVPN_CONF"
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> "$OVPN_CONF"
			echo 'push "dhcp-option DNS 94.140.15.15"' >> "$OVPN_CONF"
		;;
		7)
			echo "push \"dhcp-option DNS $dns1\"" >> "$OVPN_CONF"
			if [ -n "$dns2" ]; then
				echo "push \"dhcp-option DNS $dns2\"" >> "$OVPN_CONF"
			fi
		;;
	esac
}

create_server_config() {
	# Generate server.conf
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
	# IPv6
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
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> "$OVPN_CONF"
	fi
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

new_client() {
	get_export_dir
	# Generates the custom client.ovpn
	{
	cat "${client_common_file:-/etc/openvpn/server/client-common.txt}"
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
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > "$conf_fwd"
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> "$conf_fwd"
	fi
	# Optimize sysctl settings such as TCP buffer sizes
	base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
	conf_url="$base_url/sysctl-ovpn-$os"
	[ "$auto" != 0 ] && conf_url="${conf_url}-auto"
	wget -t 3 -T 30 -q -O "$conf_opt" "$conf_url" 2>/dev/null \
		|| curl -m 30 -fsL "$conf_url" -o "$conf_opt" 2>/dev/null \
		|| { /bin/rm -f "$conf_opt"; touch "$conf_opt"; }
	# Enable TCP BBR congestion control if kernel version >= 4.20
	if modprobe -q tcp_bbr \
		&& printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V \
		&& [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
cat >> "$conf_opt" <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
	fi
	# Apply sysctl settings
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
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				(
					set -x
					yum -y -q install policycoreutils-python >/dev/null
				) || exiterr3
			else
				# CentOS 8/9/10 or Fedora
				(
					set -x
					dnf install -y policycoreutils-python-utils >/dev/null
				) || exiterr "'dnf install' failed."
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
}

create_client_common() {
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt is created so we have a template to add further users later
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
		(
			set -x
			systemctl enable --now openvpn-server@server.service >/dev/null 2>&1
		)
	else
		ln -s /etc/openvpn/server/* /etc/openvpn >/dev/null 2>&1
		(
			set -x
			systemctl enable --now openvpn@server.service >/dev/null 2>&1
		)
	fi
}

finish_setup() {
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in: $export_dir$client.ovpn"
	echo "New clients can be added by running this script again."
}

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
	echo "  10) Remove OpenVPN"
	echo "  11) Exit"
	read -rp "Option: " option
	until [[ "$option" =~ ^([1-9]|1[01])$ ]]; do
		echo "$option: invalid selection."
		read -rp "Option: " option
	done
}

show_clients() {
	tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
}

enter_client_name() {
	echo
	echo "Provide a name for the client:"
	read -rp "Name: " unsanitized_client
	[ -z "$unsanitized_client" ] && abort_and_exit
	set_client_name
	while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
		if [ -z "$client" ]; then
			echo "Invalid client name. Use one word only, no special characters except '-' and '_'."
		else
			echo "$client: invalid name. Client already exists."
		fi
		read -rp "Name: " unsanitized_client
		[ -z "$unsanitized_client" ] && abort_and_exit
		set_client_name
	done
}

build_client_config() {
	cd /etc/openvpn/server/easy-rsa/ || exit 1
	(
		set -x
		./easyrsa --batch --days=3650 build-client-full "$client" nopass >/dev/null 2>&1
	)
}

print_client_action() {
	echo
	echo "$client $1. Configuration available in: $export_dir$client.ovpn"
}

print_check_clients() {
	echo
	echo "Checking for existing client(s)..."
}

check_clients() {
	num_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ "$num_of_clients" = 0 ]]; then
		echo
		echo "There are no existing clients!"
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
	echo
	echo "Select the client to $1:"
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

print_revoke_client() {
	echo
	echo "Revoking $client..."
}

remove_client_conf() {
	get_export_dir
	ovpn_file="$export_dir$client.ovpn"
	if [ -f "$ovpn_file" ]; then
		echo "Removing $ovpn_file..."
		rm -f "$ovpn_file"
	fi
}

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
	# CRL is read with each client connection, when OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	remove_client_conf

	# ---- FIX #4: Read the mode first, then delete the file ----
	saved_mode=$(cat "$CLIENT_META_DIR/$client.mode" 2>/dev/null)
	rm -f "$CLIENT_META_DIR/$client.mode" 2>/dev/null || true

	# Disable Linux user if certpass mode was used
	if [ "${saved_mode}" = "certpass" ]; then
		if id "$client" >/dev/null 2>&1; then
			usermod -L "$client" >/dev/null 2>&1 \
				&& echo "  [✓] Linux user '$client' disabled (locked)" \
				|| echo "  [!] Could not lock user '$client'"
		fi
	fi
	# ---- END FIX #4 ----
}

print_client_revoked() {
	echo
	echo "$client revoked!"
}

print_client_revocation_aborted() {
	echo
	echo "$client revocation aborted!"
}

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

print_remove_ovpn() {
	echo
	echo "Removing OpenVPN, please wait..."
}

disable_ovpn_service() {
	if [ "$os" != "openSUSE" ]; then
		systemctl disable --now openvpn-server@server.service
		# Also stop optional auth instance if present
		systemctl disable --now "openvpn-server@${AUTH_INSTANCE_NAME}.service" >/dev/null 2>&1 || true
	else
		systemctl disable --now openvpn@server.service
		# Also stop optional auth instance if present
		systemctl disable --now "openvpn@${AUTH_INSTANCE_NAME}.service" >/dev/null 2>&1 || true
	fi
	rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	# Clean up auth instance config
	rm -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" 2>/dev/null || true
	# Clean up hooks and bandwidth log
	rm -rf /etc/openvpn/server/hooks/ 2>/dev/null || true
	rm -f /etc/openvpn/server/bandwidth.csv 2>/dev/null || true
}

remove_sysctl_rules() {
	rm -f /etc/sysctl.d/99-openvpn-forward.conf /etc/sysctl.d/99-openvpn-optimize.conf
	if [ ! -f /usr/bin/wg-quick ] && [ ! -f /usr/sbin/ipsec ] \
		&& [ ! -f /usr/local/sbin/ipsec ]; then
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

print_ovpn_removed() {
	echo
	echo "OpenVPN removed!"
}

print_ovpn_removal_aborted() {
	echo
	echo "OpenVPN removal aborted!"
}
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
   local auth_proto
	auth_proto=$(awk '/^proto /{print $2; exit}' "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" 2>/dev/null)
	[ -z "$auth_proto" ] && auth_proto="tcp"
	# Filter for PAM auth failures via OpenVPN
	cat > /etc/fail2ban/filter.d/openvpn-auth.conf <<'EOF'
[Definition]
failregex = ^.*pam_unix\(openvpn:auth\): authentication failure.*rhost=<HOST>.*$
            ^.*openvpn.*: <HOST>:[0-9]+ TLS Error: TLS handshake failed$
            ^.*openvpn.*: <HOST>:[0-9]+ Connection reset.*$
ignoreregex =
EOF

	cat > /etc/fail2ban/jail.d/openvpn-auth.conf <<EOF
[openvpn-auth]
enabled  = true
port     = ${AUTH_PORT_DEFAULT}
protocol = ${auth_proto}
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

	# Helper: set or replace a directive
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

	# Validate config before restarting
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
	if ! command -v bc &>/dev/null; then
		echo "${bytes} B"
		return
	fi
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

	# Create the file if it does not exist
	if [ ! -f "$BANDWIDTH_LOG" ]; then
		echo "client,total_rx,total_tx,last_seen" > "$BANDWIDTH_LOG"
	fi

	while IFS=',' read -r tag cn raddr vaddr ipv6 bytes_r bytes_s since rest; do
		[ "$tag" = "CLIENT_LIST" ] || continue
		[ "$cn" = "Common Name" ] && continue
		[ -z "$cn" ] && continue

		local now
		now=$(date '+%Y-%m-%d %H:%M:%S')

		# Look up the client in the log
		local existing
		existing=$(grep "^${cn}," "$BANDWIDTH_LOG" 2>/dev/null | tail -1)

		if [ -z "$existing" ]; then
			# New client
			echo "${cn},${bytes_r},${bytes_s},${now}" >> "$BANDWIDTH_LOG"
		else
			local old_rx old_tx
			old_rx=$(echo "$existing" | cut -d',' -f2)
			old_tx=$(echo "$existing" | cut -d',' -f3)

			# Update if the new values are greater
			if [ "${bytes_r}" -ge "${old_rx}" ] 2>/dev/null; then
				# Remove the old line and add the updated one
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

	# Create or update the hook script
	cat > "$hook" <<HOOK
#!/bin/bash
source /etc/openvpn/server/hooks/api.conf 2>/dev/null

# ================================================================
# Device limit check
# ================================================================
MAX_DEVICES=\$(cat /etc/openvpn/server/hooks/max_devices 2>/dev/null || echo 1)

send_api_event() {
	[ -z "\$API_URL" ] && return
	local event="\$1"
	local reason="\${2:-}"
	local ts=\$(date -u '+%Y-%m-%dT%H:%M:%SZ')
	local payload="{\"event\":\"\${event}\",\"client\":\"\${common_name}\",\"real_ip\":\"\${trusted_ip}\",\"real_port\":\"\${trusted_port}\",\"vpn_ip\":\"\${ifconfig_pool_remote_ip}\",\"bytes_received\":\${bytes_received:-0},\"bytes_sent\":\${bytes_sent:-0},\"reason\":\"\${reason}\",\"timestamp\":\"\${ts}\"}"
	local auth_header="X-VPN-Hook: 1"
	[ -n "\$API_SECRET" ] && auth_header="Authorization: Bearer \${API_SECRET}"
	curl -sf -X POST "\$API_URL" \
		-H "Content-Type: application/json" \
		-H "\$auth_header" \
		-d "\$payload" \
		--max-time 10 >/dev/null 2>&1 &
}

if [ "\$script_type" = "client-connect" ]; then
	# Search all status files for the same CN
	active=0
	for sf in \
		/etc/openvpn/server/openvpn-status.log \
		/etc/openvpn/server/openvpn-status-auth.log; do
		[ -f "\$sf" ] || continue
		count=\$(grep "^CLIENT_LIST,\${common_name}," "\$sf" 2>/dev/null | wc -l)
		active=\$(( active + count ))
	done

	if [ "\$active" -ge "\$MAX_DEVICES" ]; then
		logger -t openvpn "REJECTED \${common_name} — already connected on \${active}/\${MAX_DEVICES} device(s)"
		send_api_event "rejected" "device_limit_exceeded"
		exit 1  # Reject the connection
	fi

	send_api_event "connect"

elif [ "\$script_type" = "client-disconnect" ]; then
	send_api_event "disconnect"
fi

exit 0
HOOK

	chmod +x "$hook"

	# Save max_devices
	echo "$max_devices" > /etc/openvpn/server/hooks/max_devices

	# Add the hooks to the configs
	add_hooks_to_conf "/etc/openvpn/server/server.conf"
	if [ -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ]; then
		add_hooks_to_conf "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf"
	fi

	echo "  [✓] Device limit set to $max_devices device(s) per client"
}

show_device_limit() {
	local current
	current=$(cat /etc/openvpn/server/hooks/max_devices 2>/dev/null || echo "not set")
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
	read -rp "  Select [1-4]: " dlopt </dev/tty
	echo

	case "$dlopt" in
		1)
			setup_device_limit 1
			;;
		2)
			read -rp "  Max devices per client [2]: " maxd </dev/tty
			[[ ! "$maxd" =~ ^[0-9]+$ ]] && maxd=2
			setup_device_limit "$maxd"
			;;
		3)
			show_device_limit
			;;
		4|"")
			return
			;;
		*)
			echo "  Invalid selection."
			;;
	esac
}

show_bandwidth_report() {
	echo
	echo "╔══════════════════════════════════════════════════════════════════╗"
	echo "║                  Bandwidth Report (All Clients)                 ║"
	echo "╚══════════════════════════════════════════════════════════════════╝"

	# Update the log from the current status files
	update_bandwidth_log "/etc/openvpn/server/openvpn-status.log"
	update_bandwidth_log "/etc/openvpn/server/openvpn-status-auth.log"

	if [ ! -f "$BANDWIDTH_LOG" ] || [ "$(wc -l < "$BANDWIDTH_LOG")" -le 1 ]; then
		echo
		echo "  No bandwidth data yet. Data is collected while clients are connected."
		echo
		return
	fi

	echo
	printf "  %-22s %-14s %-14s %-22s\n" "Client" "Download (RX)" "Upload (TX)" "Last Seen"
	echo "  ──────────────────────────────────────────────────────────────────"

	local total_rx=0 total_tx=0 count=0
	while IFS=',' read -r cn rx tx last_seen; do
		[ "$cn" = "client" ] && continue  # Skip the header
		[ -z "$cn" ] && continue

		local rx_fmt tx_fmt
		rx_fmt=$(format_bytes "$rx")
		tx_fmt=$(format_bytes "$tx")

		printf "  %-22s %-14s %-14s %-22s\n" "$cn" "$rx_fmt" "$tx_fmt" "$last_seen"

		total_rx=$(( total_rx + rx ))
		total_tx=$(( total_tx + tx ))
		(( count++ ))
	done < <(tail -n +2 "$BANDWIDTH_LOG" | sort -t',' -k1)

	echo "  ──────────────────────────────────────────────────────────────────"
	printf "  %-22s %-14s %-14s\n" \
		"Total ($count clients)" \
		"$(format_bytes "$total_rx")" \
		"$(format_bytes "$total_tx")"
	echo
}

show_active_vpn_users() {
	local status_main="/etc/openvpn/server/openvpn-status.log"
	local status_auth="/etc/openvpn/server/openvpn-status-auth.log"

	echo
	echo "╔══════════════════════════════════════════════════════════╗"
	echo "║              Active VPN Users                           ║"
	echo "╚══════════════════════════════════════════════════════════╝"

	# Ensure status exists in server.conf
	if ! grep -q "^status " /etc/openvpn/server/server.conf 2>/dev/null; then
		echo
		echo "  [!] Adding 'status' directive to server.conf..."
		echo "status openvpn-status.log" >> /etc/openvpn/server/server.conf
		systemctl restart "$(get_service_name "/etc/openvpn/server/server.conf").service" >/dev/null 2>&1
		sleep 2
		echo "  [✓] Done. OpenVPN restarted."
	fi

	parse_and_show_status() {
		local file="$1"
		local label="$2"

		[ -f "$file" ] || { echo "  (status file not found: $file)"; return; }

		echo
		echo "  ── $label ──"
		echo "  Updated: $(grep '^TIME,' "$file" | awk -F',' '{print $2}')"
		echo
		printf "  %-20s %-22s %-16s %-12s %-12s %s\n" "Client Name" "Real IP:Port" "Virtual IP" "Download" "Upload" "Connected Since"
		echo "  ───────────────────────────────────────────────────────────────────────"

		local count=0
		while IFS=',' read -r tag cn raddr vaddr _ bytes_r bytes_s since _; do
			[ "$tag" = "CLIENT_LIST" ] || continue
			[ "$cn" = "Common Name" ] && continue
			local rx_fmt tx_fmt
			rx_fmt=$(format_bytes "$bytes_r")
			tx_fmt=$(format_bytes "$bytes_s")
			printf "  %-20s %-22s %-16s %-12s %-12s %s\n" "$cn" "$raddr" "$vaddr" "$rx_fmt" "$tx_fmt" "$since"
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
		# ---- FIX #3 (part B): Add status only if it is missing, one line only ----
		if ! grep -q "^status " "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" 2>/dev/null; then
			echo "  [!] Adding 'status' directive to auth.conf..."
			echo "status openvpn-status-auth.log" >> "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf"
			systemctl restart "$(get_service_name "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf").service" >/dev/null 2>&1
			sleep 2
			echo "  [✓] Done. Auth service restarted."
		fi
		# ---- END FIX #3 (part B) ----
		parse_and_show_status "$status_auth" \
			"Auth Server (cert+pass) — port ${AUTH_PORT_DEFAULT}"
	fi

	echo
}

show_fail2ban_status() {
	echo
	echo "  ── fail2ban Status ──"
	if ! systemctl is-active --quiet fail2ban; then
		echo "  fail2ban is not running."
		return
	fi
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
	read -rp "Select [1-7]: " sec_opt </dev/tty
	echo

	case "$sec_opt" in
		1)
			install_fail2ban
			setup_fail2ban_ssh
			;;
		2)
			if [ ! -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ]; then
				echo "  OpenVPN auth instance not set up yet. Add a certpass client first."
			else
				install_fail2ban
				setup_fail2ban_openvpn_auth
			fi
			;;
		3)
			install_fail2ban
			setup_fail2ban_ssh
			if [ -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ]; then
				setup_fail2ban_openvpn_auth
			else
				echo "  (Skipping OpenVPN jail — auth instance not active)"
			fi
			;;
		4)
			harden_ssh
			;;
		5)
			install_fail2ban
			setup_fail2ban_ssh
			if [ -f "/etc/openvpn/server/${AUTH_INSTANCE_NAME}.conf" ]; then
				setup_fail2ban_openvpn_auth
			fi
			harden_ssh
			;;
		6)
			show_fail2ban_status
			;;
		7|"")
			return
			;;
		*)
			echo "Invalid selection."
			;;
	esac
}

# ============================================================
# BACKUP & RESTORE
# ============================================================

BACKUP_DIR="/etc/openvpn/backups"

create_backup() {
	mkdir -p "$BACKUP_DIR"

	local timestamp
	timestamp=$(date '+%Y%m%d_%H%M%S')
	local backup_file="$BACKUP_DIR/openvpn_backup_${timestamp}.tar.gz"
	local extra_files=()
	echo
	echo "  Creating backup..."
	[ -f /etc/openvpn/server/verify-cn.sh ] && extra_files+=("/etc/openvpn/server/verify-cn.sh")
	[ -f /etc/pam.d/openvpn ] && extra_files+=("/etc/pam.d/openvpn")
	# Backup Important Files
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
		"${extra_files[@]}" \
		2>/dev/null

	if [ $? -eq 0 ]; then
		local size
		size=$(du -sh "$backup_file" | cut -f1)
		chmod 600 "$backup_file"
		echo "  [✓] Backup created: $backup_file ($size)"
		echo
		echo "  To download via SCP:"
		echo "    scp root@$(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_IP'):$backup_file ."
	else
		echo "  [✗] Backup failed!"
		rm -f "$backup_file"
	fi
}

list_backups() {
	echo
	if [ ! -d "$BACKUP_DIR" ] || [ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]; then
		echo "  No backups found in $BACKUP_DIR"
		return 1
	fi

	echo "  Available backups:"
	echo
	local i=1
	while IFS= read -r f; do
		local size date_str
		size=$(du -sh "$f" | cut -f1)
		date_str=$(basename "$f" | sed 's/openvpn_backup_//;s/.tar.gz//;s/_/ /;s/\(..\)\(..\)\(..\)$/:\1:\2/')
		printf "   %d) %-45s %s\n" "$i" "$(basename "$f")" "($size)"
		(( i++ ))
	done < <(ls -t "$BACKUP_DIR"/openvpn_backup_*.tar.gz 2>/dev/null)

	return 0
}

restore_backup() {
	list_backups || return

	local files=()
	while IFS= read -r f; do
		files+=("$f")
	done < <(ls -t "$BACKUP_DIR"/openvpn_backup_*.tar.gz 2>/dev/null)

	echo
	read -rp "  Select backup number (or Enter to cancel): " sel </dev/tty
	[ -z "$sel" ] && return
	if [[ ! "$sel" =~ ^[0-9]+$ ]] || [ "$sel" -lt 1 ] || [ "$sel" -gt "${#files[@]}" ]; then
		echo "  Invalid selection."
		return
	fi

	local chosen="${files[$((sel-1))]}"
	echo
	echo "  Selected: $(basename "$chosen")"
	echo
	echo "  ⚠ WARNING: This will OVERWRITE current OpenVPN configuration!"
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
		1) keep=3 ;;
		2) keep=1 ;;
		3) keep=0 ;;
		4|"") return ;;
		*) echo "  Invalid."; return ;;
	esac

	if [ "$keep" -eq 0 ]; then
		read -rp "  Delete ALL backups? [y/N]: " confirm </dev/tty
		[[ ! "$confirm" =~ ^[yY]$ ]] && { echo "  Cancelled."; return; }
		rm -f "$BACKUP_DIR"/openvpn_backup_*.tar.gz
		echo "  [✓] All backups deleted."
	else
		# Delete everything except the latest $keep backups
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
	read -rp "  Select [1-5]: " br_opt </dev/tty
	echo

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
server_proto="TCP"
server_port=""
first_client_name=""
unsanitized_client=""
client=""
dns=""
dns1=""
dns2=""

parse_args "$@"
check_args

if [ "$add_client" = 1 ]; then
	show_header
	echo
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
	build_client_config
	new_client
	print_client_action added
	exit 0
fi

if [ "$export_client" = 1 ]; then
	show_header
	load_client_mode
	if [ "$mode" = "certpass" ]; then
		ensure_auth_instance
	fi
	new_client
	print_client_action exported
	exit 0
fi

if [ "$list_clients" = 1 ]; then
	show_header
	print_check_clients
	check_clients
	echo
	show_clients
	print_client_total
	exit 0
fi

if [ "$revoke_client" = 1 ]; then
	show_header
	confirm_revoke_client
	if [[ "$revoke" =~ ^[yY]$ ]]; then
		print_revoke_client
		revoke_client_ovpn
		print_client_revoked
		exit 0
	else
		print_client_revocation_aborted
		exit 1
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
		print_ovpn_removed
		exit 0
	else
		print_ovpn_removal_aborted
		exit 1
	fi
fi

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
	if [ "$auto" = 0 ]; then
		select_dns
	fi
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
	if [ "$os" != "openSUSE" ]; then
		update_rclocal
	fi
	update_selinux
	create_client_common
	start_openvpn_service
	new_client
	if [ "$auto" != 0 ] && check_dns_name "$server_addr"; then
		show_dns_name_note "$server_addr"
	fi
	finish_setup
else
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
			build_client_config
			new_client
			print_client_action added
			exit 0
		;;
		2)
			check_clients
			select_client_to export
			load_client_mode
			if [ "$mode" = "certpass" ]; then
				ensure_auth_instance
			fi
			new_client
			print_client_action exported
			exit 0
		;;
		3)
			print_check_clients
			check_clients
			echo
			show_clients
			print_client_total
			exit 0
		;;
		4)
			check_clients
			select_client_to revoke
			confirm_revoke_client
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				print_revoke_client
				revoke_client_ovpn
				print_client_revoked
				exit 0
			else
				print_client_revocation_aborted
				exit 1
			fi
		;;
		5)
			show_active_vpn_users
			exit 0
		;;
		6)
			show_bandwidth_report
			exit 0
		;;
		7)
			run_api_setup
			exit 0
		;;
		8)
			run_security_setup
			exit 0
		;;
		9)
			run_backup_restore
			exit 0
		;;
		10)
			confirm_remove_ovpn
			if [[ "$remove" =~ ^[yY]$ ]]; then
				print_remove_ovpn
				remove_firewall_rules
				disable_ovpn_service
				remove_sysctl_rules
				remove_rclocal_rules
				remove_pkgs
				print_ovpn_removed
				exit 0
			else
				print_ovpn_removal_aborted
				exit 1
			fi
		;;
		11)
			exit 0
		;;
	esac
fi
}

## Defer setup until we have the complete script
ovpnsetup "$@"

exit 0
