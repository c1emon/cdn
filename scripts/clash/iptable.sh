#!/bin/sh

set -e

proxylocal=0

fakeiponly=0
fakeip="198.18.0.0/16"

CLASH_USER="clash"

tproxyport="7893"

redirectdns=0
redirectdnsport="1053"

routetable=0xc1a56
routemark=888

chainclash="clash"
chainlocal="clash_local"

chainmark='0xc1a56'

# 
# set=1
# clean=2
action=0

DRY_RUN=${DRY_RUN:-}

help() {
    cat <<EOF
Usage: sudo iptable.sh [options] command

command:
    set
    clean

options:
    --fakeip            string          Fake ip cidr (default ${fakeip})
    --fakeip-only       flag            Only tproxy fake ip range (default false)
    --proxy-local       flag            Proxy local host (default false)
    --redirect-dns      flag            Redirect dns(UDP 53) to clash (default false)
    --redirect-dns-port string          Redirect dns(UDP 53) to clash(UDP ${redirectdnsport}) (default false)
    --tproxy-port       string          Clash port for tproxy (default ${tproxyport})
    --user              string          Service user (default ${CLASH_USER})
    --dry-run           flag            Dry run (default false)
    --help              flag            Show this message

example:
    sudo iptable.sh --proxy-local --tproxy-port --user clash set
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
        set)
            action=1
            ;;
        clean)
            action=2
            ;;
        --proxy-local)
            proxylocal=1
            ;;
        --fakeip-only)
            fakeiponly=1
            ;;
        --redirect-dns)
            redirectdns=1
            ;;
        --fakeip)
            fakeip="$2"
            shift
            ;;
        --tproxy-port)
            tproxyport="$2"
            shift
            ;;
        --user)
			CLASH_USER="$2"
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

set_ipt() {
    # ENABLE ipv4 forward
    $SH_C "sysctl -w net.ipv4.ip_forward=1"

    # ROUTE RULES
    $SH_C "ip rule add fwmark ${routemark} lookup ${routetable}"
    $SH_C "ip route add local 0.0.0.0/0 dev lo table ${routetable}"

    # ${chainclash} 链负责处理转发流量
    $SH_C "iptables -t mangle -N ${chainclash}"

    ipt_fakeip_opt=""
    if [ "${fakeiponly}" = "1" ]; then
        ipt_fakeip_opt="-d ${fakeip}"
    else
        # 目标地址为局域网或保留地址的流量跳过处理
        # 保留地址参考: https://zh.wikipedia.org/wiki/%E5%B7%B2%E5%88%86%E9%85%8D%E7%9A%84/8_IPv4%E5%9C%B0%E5%9D%80%E5%9D%97%E5%88%97%E8%A1%A8
        $SH_C "iptables -t mangle -A ${chainclash} -d 0.0.0.0/8 -j RETURN"
        $SH_C "iptables -t mangle -A ${chainclash} -d 127.0.0.0/8 -j RETURN"
        $SH_C "iptables -t mangle -A ${chainclash} -d 10.0.0.0/8 -j RETURN"
        $SH_C "iptables -t mangle -A ${chainclash} -d 172.16.0.0/12 -j RETURN"
        $SH_C "iptables -t mangle -A ${chainclash} -d 192.168.0.0/16 -j RETURN"
        $SH_C "iptables -t mangle -A ${chainclash} -d 169.254.0.0/16 -j RETURN"

        $SH_C "iptables -t mangle -A ${chainclash} -d 224.0.0.0/4 -j RETURN"
        $SH_C "iptables -t mangle -A ${chainclash} -d 240.0.0.0/4 -j RETURN"
    fi

    # 其他所有流量转向到 ${tproxyport} 端口，并打上 mark
    $SH_C "iptables -t mangle -A ${chainclash} -p tcp -j TPROXY --on-port ${tproxyport} --tproxy-mark ${routemark}"
    $SH_C "iptables -t mangle -A ${chainclash} -p udp -j TPROXY --on-port ${tproxyport} --tproxy-mark ${routemark}"

    # 最后让所有流量通过 clash 链进行处理
    $SH_C "iptables -t mangle -A PREROUTING ${ipt_fakeip_opt} -m comment --comment ${chainmark} -j ${chainclash}"
    
    # 跳过 clash 程序本身发出的流量, 防止死循环(clash 程序需要使用 "${CLASH_USER}" 用户启动) 
    $SH_C "iptables -t mangle -A OUTPUT -p tcp -m comment --comment ${chainmark} -m owner --uid-owner ${CLASH_USER} -j RETURN"
    $SH_C "iptables -t mangle -A OUTPUT -p udp -m comment --comment ${chainmark} -m owner --uid-owner ${CLASH_USER} -j RETURN"

    if [ "${proxylocal}" = "1" ]; then
        echo "proxy local traefik"
        # ${chainlocal} 链负责处理网关本身发出的流量
        $SH_C "iptables -t mangle -N ${chainlocal}"

        ipt_fakeip_opt=""
        if [ "${fakeiponly}" = "1" ]; then
            ipt_fakeip_opt="-d ${fakeip}"
        else
            # nerdctl 容器流量重新路由
            #$SH_C "iptables -t mangle -A ${chainlocal} -i nerdctl2 -p udp -j MARK --set-mark ${routemark}"
            #$SH_C "iptables -t mangle -A ${chainlocal} -i nerdctl2 -p tcp -j MARK --set-mark ${routemark}"

            # 跳过内网流量
            $SH_C "iptables -t mangle -A ${chainlocal} -d 0.0.0.0/8 -j RETURN"
            $SH_C "iptables -t mangle -A ${chainlocal} -d 127.0.0.0/8 -j RETURN"
            $SH_C "iptables -t mangle -A ${chainlocal} -d 10.0.0.0/8 -j RETURN"
            $SH_C "iptables -t mangle -A ${chainlocal} -d 172.16.0.0/12 -j RETURN"
            $SH_C "iptables -t mangle -A ${chainlocal} -d 192.168.0.0/16 -j RETURN"
            $SH_C "iptables -t mangle -A ${chainlocal} -d 169.254.0.0/16 -j RETURN"

            $SH_C "iptables -t mangle -A ${chainlocal} -d 224.0.0.0/4 -j RETURN"
            $SH_C "iptables -t mangle -A ${chainlocal} -d 240.0.0.0/4 -j RETURN"

        fi

        # 为本机发出的流量打 mark
        $SH_C "iptables -t mangle -A ${chainlocal} -p tcp -j MARK --set-mark ${routemark}"
        $SH_C "iptables -t mangle -A ${chainlocal} -p udp -j MARK --set-mark ${routemark}"

        # 让本机发出的流量跳转到 ${chainlocal}
        # ${chainlocal} 链会为本机流量打 mark, 打过 mark 的流量会重新回到 PREROUTING 上
        $SH_C "iptables -t mangle -A OUTPUT ${ipt_fakeip_opt} -m comment --comment ${chainmark} -j ${chainlocal}"
    fi
    
    if [ "${redirectdns}" = "1" ]; then
        echo "redirect dns"
        # 转发所有 DNS 查询到 ${redirectdnsport} 端口
        # 此操作会导致所有 DNS 请求全部返回虚假 IP(fake ip 198.18.0.1/16)
        $SH_C "iptables -t nat -I PREROUTING -p udp --dport 53 -m comment --comment ${chainmark} -j REDIRECT --to ${redirectdnsport}"

        # 如果想要 dig 等命令可用, 可以只处理 DNS SERVER 设置为当前内网的 DNS 请求
        # $SH_C "iptables -t nat -I PREROUTING -p udp --dport 53 -d 192.168.0.0/16 -j REDIRECT --to ${redirectdnsport}"
    fi

    # fix ICMP(ping)
    # just a fake fix, not real send ICMP package to target host
    # --to-destination set to an available address like 127.0.0.1
    # $SH_C "sysctl -w net.ipv4.conf.all.route_localnet=1"
    # $SH_C "iptables -t nat -A PREROUTING -p icmp -d ${fakeip} -m comment --comment ${chainmark} -j DNAT --to-destination 127.0.0.1"
}

delete_ipt_rule_by_marker() {
    table=$1
    chain=$2
    marker=$3
    
    while true; do
        line_num=$($SH_C "iptables -t ${table} -L ${chain} --line-numbers | grep \"${marker}\" | head -n 1 | awk '{print \$1}'")
        if [ "${line_num}" -gt 0 ] 2>/dev/null; then
            echo "delete rule ${line_num} of ${table} ${chain}"
            $SH_C "iptables -t ${table} -D ${chain} ${line_num}"
        else
            break
        fi
    done
    
}

delete_ipt_custom_chain() {
    table=$1
    name=$2

    $SH_C "iptables -t ${table} -F ${name} || true"
    $SH_C "iptables -t ${table} -X ${name} || true"
}

clean_ipt() {
    $SH_C "ip rule del fwmark ${routemark} table ${routetable} || true"
    $SH_C "ip route del local 0.0.0.0/0 dev lo table ${routetable} || true"

    echo "delete iptable proxy rule"
    delete_ipt_rule_by_marker "mangle" "PREROUTING" "${chainmark}"

    echo "delete chain ${chainclash}"
    delete_ipt_custom_chain "mangle" "${chainclash}"

    delete_ipt_rule_by_marker "mangle" "OUTPUT" "${chainmark}"
    if [ "${proxylocal}" = "1" ]; then
        echo "delete iptable proxy-local rule"
        delete_ipt_custom_chain "mangle" "${chainlocal}"
    fi

    if [ "${redirectdns}" = "1" ]; then
        echo "delete iptable dns redirect rule"
        delete_ipt_rule_by_marker "nat" "PREROUTING" "${chainmark}"
    fi
}

check_root
prepare_sh
case "${action}" in
    1)
        echo "setting iptable ..."
        set_ipt
        echo "setting iptable done"
    ;;
    2)
        echo "cleaning iptable ..."
        clean_ipt
        echo "cleaning iptable done"
    ;;
    0)
        echo "error: unknown command"
        exit 3
    ;;
esac
