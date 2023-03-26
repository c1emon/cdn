#!/bin/sh
set -e

DEFAULT_DOWNLOAD_URL="https://github.com/Dreamacro/clash/releases/download"
SCRIPTS_DOWNLOAD_URL="https://cdn.jsdelivr.net/gh/c1emon/cdn/scripts"

install=0
premium=0
mirror='Github'
version=''

DRY_RUN=${DRY_RUN:-}

CLASH_EXEC="/usr/bin"
CLASH_HOME="/etc/clash"
CLASH_USER='clash'
CLASH_GROUP='clash'

noipt=0
ipt_options=""

help() {
    cat <<EOF
Install clash for linux with systemd.
Usage: sudo get-clash.sh [options] command

command:
    install
    uninstall

options:
    --premium           flag            Use clash premium (default false)
    --mirror            enum            Download mirror (default Github), avaliable options:
                                        Github (${DEFAULT_DOWNLOAD_URL})
    --version           string          Clash version (required)
    --no-ipt            flag            Disable iptable scripts (default false)

    iptable options:
    --fakeip            string          Fake ip cidr (default 198.18.0.0/16)
    --fakeip-only       flag            Only tproxy fake ip range (default false)
    --proxy-local       flag            Proxy local host (default false)
    --tproxy-port       flag            Port for tproxy (default 7893)
    --redirect-dns      flag            Redirect dns(UDP 53) to clash (default false)
    --redirect-dns-port string          DNS Redirect target port (default UDP 1053)

    --user              string          Service user (default ${CLASH_USER})
    --group             string          Service group (default ${CLASH_GROUP})
    --bin               string          Clash bin path (default ${CLASH_EXEC})
    --conf              string          Clash conf path/working dir (default ${CLASH_HOME})
    --dry-run           flag            Dry run (default false)
    --help              flag            Show this message

example:
    sudo get-clash.sh --no-ipt --version v1.14.0 --user clash install
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
        install)
            install=1
            ;;
        uninstall)
            install=-1
            ;;
		--premium)
			premium=0
			;;
        --no-ipt)
			noipt=1
			;;
        --fakeip-only)
            ipt_options="${ipt_options} --fakeip-only"
            ;;
        --proxy-local)
            ipt_options="${ipt_options} --proxy-local"
            ;;
        --redirect-dns)
            ipt_options="${ipt_options} --redirect-dns"
            ;;
        --fakeip)
            ipt_options="${ipt_options} --fakeip $2"
            shift
            ;;
        --tproxy-port)
            ipt_options="${ipt_options} --tproxy-port $2"
            shift
            ;;
        --redirect-dns-port)
            ipt_options="${ipt_options} --redirect-dns-port $2"
            shift
            ;;
        --mirror)
			mirror="$2"
			shift
			;;
        --version)
			version="$2"
			shift
			;;
        --user)
			CLASH_USER="$2"
			shift
			;;
        --group)
			CLASH_GROUP="$2"
			shift
			;;
        --bin)
			CLASH_EXEC="$2"
			shift
			;;
        --conf)
			CLASH_HOME="$2"
			shift
			;;
        --dry-run)
			DRY_RUN=1
			;;
        --help)
			help
            exit 0
			;;    
		--*)
			echo "Illegal option $1"
			;;
	esac
	shift $(( $# > 0 ? 1 : 0 ))
done

command_exists() {
	command -v "$@" > /dev/null 2>&1
}

is_dry_run() {
	if [ -z "${DRY_RUN}" ]; then
		return 1
	else
		return 0
	fi
}

is_linux() {
	case "$(uname -s)" in
	*linux* ) true ;;
	*Linux* ) true ;;
	* ) false;;
	esac
}

is_systemd() {
    command_exists systemctl
}

is_ipt() {
    command_exists iptables
}

get_arch() {
    arch="$(uname -i)"
    case "${arch}" in
    x86_64|amd64)
        echo "amd64";;
    i?86)
        echo "i386";;
    armv*|aarch*)
        echo "${arch}";;
    powerpc|ppc64)
        echo "powerpc";;
	* ) echo "unknown";;
    esac
}

SH_C='sh -c'
prepare_sh() {
    user="$(id -un 2>/dev/null || true)"

    if is_dry_run; then
		SH_C="echo"
        echo "Dry run"
        return
	fi

    if [ "$user" != 'root' ]; then
		if command_exists sudo; then
			SH_C='sudo -E sh -c'
		elif command_exists su; then
			SH_C='su -c'
		else
			cat >&2 <<-'EOF'
			Error: this installer needs the ability to run commands as root.
			We are unable to find either "sudo" or "su" available to make this happen.
			EOF
			exit 1
		fi
	fi
    
    return
}

check_root() {
    if is_dry_run; then
        return
	fi
    if [ "$(id -u)" != "0" ]; then
    >&2 echo "ERROR: Not running as root. Please run as root."
    exit 120
    fi
}

create_user_group() {
    if [ ! "$(getent group "${CLASH_GROUP}")" ]; then
        $SH_C "addgroup ${CLASH_GROUP}"
    fi

    if [ ! "$(getent passwd "${CLASH_USER}")" ]; then
        $SH_C "useradd -M -s /bin/false -d ${CLASH_HOME} -g ${CLASH_GROUP} ${CLASH_USER}"
    fi
}

if [ -z "$DOWNLOAD_URL" ]; then
	DOWNLOAD_URL=$DEFAULT_DOWNLOAD_URL
fi

install_bin() {

    arch=$(get_arch)
    url=''

    if [ "${arch}" = "unknown" ]; then
        echo "error: unknown arch"
        exit 2
    fi

    if [ ${premium} = "0" ]; then
        url="${DOWNLOAD_URL}/${version}/clash-linux-${arch}-${version}.gz"
    else
        url="${DOWNLOAD_URL}/premium/clash-linux-${arch}-${version}.gz"
    fi
    
    $SH_C "curl -LJ ${url} -o /tmp/clash.gz"
    $SH_C "gzip -d /tmp/clash.gz"
    $SH_C "mv /tmp/clash ${CLASH_EXEC}/clash"
    $SH_C "chmod +x ${CLASH_EXEC}/clash"

    echo "install clash to ${CLASH_EXEC}"
}

install_service() {

    $SH_C "cat > /lib/systemd/system/clash.service <<EOF
[Unit]
Description=Clash TProxy
After=network.target

[Service]
Type=simple
User=${CLASH_USER}
Group=${CLASH_GROUP}
WorkingDirectory=${CLASH_HOME}
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
Restart=on-failure

EOF"

if [ "${noipt}" = "0" ]; then
    $SH_C "cat >> /lib/systemd/system/clash.service <<EOF
ExecStartPre=+/usr/bin/bash ${CLASH_HOME}/iptable.sh ${ipt_options} clean
ExecStart=${CLASH_EXEC}/clash -d ${CLASH_HOME}
ExecStartPost=+/usr/bin/bash ${CLASH_HOME}/iptable.sh ${ipt_options} set
ExecStopPost=+/usr/bin/bash ${CLASH_HOME}/iptable.sh ${ipt_options} clean
EOF"
else
    $SH_C "cat >> /lib/systemd/system/clash.service <<EOF
ExecStart=${CLASH_EXEC}/clash -d ${CLASH_HOME}
EOF"
fi

$SH_C "cat >> /lib/systemd/system/clash.service <<EOF

[Install]
WantedBy=multi-user.target
EOF"
}

install_ipt() {
    if [ ! -d "${CLASH_HOME}" ]; then
        echo "${CLASH_HOME} didn't exist, making dir..."
        $SH_C "mkdir ${CLASH_HOME}"
    fi
    
    echo "Installing files in ${CLASH_HOME}..."
    $SH_C "curl -L ${SCRIPTS_DOWNLOAD_URL}/clash/iptable.sh -o ${CLASH_HOME}/iptable.sh"
    $SH_C "chmod +x ${CLASH_HOME}/iptable.sh"

    echo "fix promission for ${CLASH_HOME}"
    $SH_C "chown -R ${CLASH_USER}:${CLASH_GROUP} ${CLASH_HOME}"
}

do_install() {
    echo "# Executing clash install script"

    if ! is_linux; then
		echo
		echo "error: can't install for non-linux system"
		exit 100
	fi

    if ! is_systemd; then
		echo
		echo "error: can't install for non-systemd system"
		exit 101
	fi

    if ! is_ipt; then
        echo
		echo "error: can't install for non-iptable system"
		exit 101
    fi

    if [ -z "$version" ]; then
        echo
        echo "error: invaild param \"version\""
        exit 102
    fi

    create_user_group

    install_bin
    install_service
    if [ "${noipt}" = "0" ]; then
        install_ipt
    fi
}

do_uninstall() {
    $SH_C "systemctl stop clash && systemctl disable clash"
    $SH_C "rm -rf ${CLASH_EXEC}/clash /lib/systemd/system/clash.service"
    echo "Mannual delete ${CLASH_HOME} and user:${CLASH_USER} group:${CLASH_GROUP}"
}

check_root
prepare_sh
case "${install}" in
    1)
        echo "installing ..."
        do_install
        echo "install finished"
    ;;
    -1)
        echo "uninstalling ..."
        do_uninstall
        echo "uninstall finished"
    ;;
    0)
        echo "error: unknown command"
        exit 3
    ;;
esac
