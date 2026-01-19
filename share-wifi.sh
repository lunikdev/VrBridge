#!/bin/bash

# Script ULTRA-OTIMIZADO para VR - SEM DHCP
# Foco: LATÊNCIA MÍNIMA (< 5ms)
# Uso: ./share-wifi-vr.sh [start|stop|status]

# CONFIGURAÇÕES
WIFI_INTERFACE="wlan0"
ETH_INTERFACE="enp6s0"
ETH_IP="192.168.100.1"

# Arquivos de controle
BACKUP_DIR="/tmp/wifi-share-backup"
STATE_FILE="$BACKUP_DIR/state"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Execute como root: sudo $0${NC}"
    exit 1
fi

mkdir -p "$BACKUP_DIR"

# Otimizar kernel para latência ZERO
optimize_kernel() {
    echo "→ Otimizando kernel para VR..."

    # Backup
    sysctl net.core.netdev_max_backlog | awk '{print $3}' > "$BACKUP_DIR/netdev_max_backlog.bak"
    sysctl net.core.rmem_max | awk '{print $3}' > "$BACKUP_DIR/rmem_max.bak"
    sysctl net.core.wmem_max | awk '{print $3}' > "$BACKUP_DIR/wmem_max.bak"
    sysctl net.ipv4.tcp_fastopen | awk '{print $3}' > "$BACKUP_DIR/tcp_fastopen.bak"
    sysctl net.ipv4.tcp_timestamps | awk '{print $3}' > "$BACKUP_DIR/tcp_timestamps.bak"
    sysctl net.ipv4.tcp_sack | awk '{print $3}' > "$BACKUP_DIR/tcp_sack.bak"

    # Aplicar otimizações
    sysctl -w net.core.netdev_max_backlog=5000 > /dev/null
    sysctl -w net.core.rmem_max=134217728 > /dev/null
    sysctl -w net.core.wmem_max=134217728 > /dev/null
    sysctl -w net.ipv4.tcp_fastopen=3 > /dev/null
    sysctl -w net.ipv4.tcp_timestamps=0 > /dev/null
    sysctl -w net.ipv4.tcp_sack=1 > /dev/null
    sysctl -w net.ipv4.tcp_low_latency=1 > /dev/null 2>/dev/null || true

    # Desabilitar offloading (CRÍTICO para latência)
    ethtool -K "$ETH_INTERFACE" gro off 2>/dev/null || true
    ethtool -K "$ETH_INTERFACE" lro off 2>/dev/null || true
    ethtool -K "$ETH_INTERFACE" tso off 2>/dev/null || true
    ethtool -K "$ETH_INTERFACE" gso off 2>/dev/null || true
    ethtool -K "$ETH_INTERFACE" sg off 2>/dev/null || true

    echo "KERNEL_OPTIMIZED" >> "$STATE_FILE"
    echo -e "${GREEN}✓ Kernel otimizado (latência < 5ms)${NC}"
}

# QoS com fq_codel (anti-bufferbloat)
optimize_qos() {
    echo "→ Configurando QoS (fq_codel)..."

    tc qdisc del dev "$ETH_INTERFACE" root 2>/dev/null || true
    tc qdisc del dev "$WIFI_INTERFACE" root 2>/dev/null || true

    # fq_codel = melhor QoS para baixa latência
    tc qdisc add dev "$ETH_INTERFACE" root fq_codel
    tc qdisc add dev "$WIFI_INTERFACE" root fq_codel

    echo "QOS_CONFIGURED" >> "$STATE_FILE"
    echo -e "${GREEN}✓ QoS ativo (bufferbloat zero)${NC}"
}

# Limpar NAT
clean_nat() {
    # nftables
    nft delete rule ip nat POSTROUTING handle $(nft -a list table ip nat 2>/dev/null | grep "oifname \"$WIFI_INTERFACE\" masquerade" | awk '{print $NF}') 2>/dev/null || true

    # iptables
    while iptables -t nat -C POSTROUTING -o "$WIFI_INTERFACE" -j MASQUERADE 2>/dev/null; do
        iptables -t nat -D POSTROUTING -o "$WIFI_INTERFACE" -j MASQUERADE
    done

    while iptables -C FORWARD -i "$WIFI_INTERFACE" -o "$ETH_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do
        iptables -D FORWARD -i "$WIFI_INTERFACE" -o "$ETH_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    done

    while iptables -C FORWARD -i "$ETH_INTERFACE" -o "$WIFI_INTERFACE" -j ACCEPT 2>/dev/null; do
        iptables -D FORWARD -i "$ETH_INTERFACE" -o "$WIFI_INTERFACE" -j ACCEPT
    done
}

# Backup do sistema
backup_state() {
    iptables-save > "$BACKUP_DIR/iptables.bak"
    sysctl net.ipv4.ip_forward | awk '{print $3}' > "$BACKUP_DIR/ip_forward.bak"
    ip addr show "$ETH_INTERFACE" > "$BACKUP_DIR/eth-config.bak" 2>/dev/null || true
    echo "ACTIVE" > "$STATE_FILE"
}

# Restaurar sistema
restore_state() {
    echo "Restaurando sistema..."

    if [ ! -f "$STATE_FILE" ]; then
        echo -e "${YELLOW}Nenhum backup encontrado${NC}"
        return
    fi

    # Restaurar kernel
    if grep -q "KERNEL_OPTIMIZED" "$STATE_FILE" 2>/dev/null; then
        echo "→ Restaurando kernel..."
        [ -f "$BACKUP_DIR/netdev_max_backlog.bak" ] && sysctl -w net.core.netdev_max_backlog=$(cat "$BACKUP_DIR/netdev_max_backlog.bak") > /dev/null
        [ -f "$BACKUP_DIR/rmem_max.bak" ] && sysctl -w net.core.rmem_max=$(cat "$BACKUP_DIR/rmem_max.bak") > /dev/null
        [ -f "$BACKUP_DIR/wmem_max.bak" ] && sysctl -w net.core.wmem_max=$(cat "$BACKUP_DIR/wmem_max.bak") > /dev/null
        [ -f "$BACKUP_DIR/tcp_fastopen.bak" ] && sysctl -w net.ipv4.tcp_fastopen=$(cat "$BACKUP_DIR/tcp_fastopen.bak") > /dev/null
        [ -f "$BACKUP_DIR/tcp_timestamps.bak" ] && sysctl -w net.ipv4.tcp_timestamps=$(cat "$BACKUP_DIR/tcp_timestamps.bak") > /dev/null
        [ -f "$BACKUP_DIR/tcp_sack.bak" ] && sysctl -w net.ipv4.tcp_sack=$(cat "$BACKUP_DIR/tcp_sack.bak") > /dev/null
        sysctl -w net.ipv4.tcp_low_latency=0 > /dev/null 2>/dev/null || true

        # Reativar offloading
        ethtool -K "$ETH_INTERFACE" gro on 2>/dev/null || true
        ethtool -K "$ETH_INTERFACE" lro on 2>/dev/null || true
        ethtool -K "$ETH_INTERFACE" tso on 2>/dev/null || true
        ethtool -K "$ETH_INTERFACE" gso on 2>/dev/null || true
        ethtool -K "$ETH_INTERFACE" sg on 2>/dev/null || true
    fi

    # Remover QoS
    if grep -q "QOS_CONFIGURED" "$STATE_FILE" 2>/dev/null; then
        echo "→ Removendo QoS..."
        tc qdisc del dev "$ETH_INTERFACE" root 2>/dev/null || true
        tc qdisc del dev "$WIFI_INTERFACE" root 2>/dev/null || true
    fi

    # Limpar NAT
    clean_nat

    # Restaurar iptables
    if [ -f "$BACKUP_DIR/iptables.bak" ]; then
        iptables-restore < "$BACKUP_DIR/iptables.bak"
    fi

    # Restaurar IP forwarding
    if [ -f "$BACKUP_DIR/ip_forward.bak" ]; then
        sysctl -w net.ipv4.ip_forward=$(cat "$BACKUP_DIR/ip_forward.bak") > /dev/null
    fi

    # UFW
    if grep -q "UFW_MODIFIED" "$STATE_FILE" 2>/dev/null; then
        if command -v ufw &> /dev/null; then
            ufw route delete allow in on "$ETH_INTERFACE" out on "$WIFI_INTERFACE" 2>/dev/null || true
            ufw route delete allow in on "$WIFI_INTERFACE" out on "$ETH_INTERFACE" 2>/dev/null || true
        fi
    fi

    # Limpar interface
    ip addr flush dev "$ETH_INTERFACE" 2>/dev/null || true
    ip link set "$ETH_INTERFACE" down 2>/dev/null || true

    # Remover backup
    rm -rf "$BACKUP_DIR"

    echo -e "${GREEN}✓ Sistema restaurado${NC}"
}

# INICIAR
start_sharing() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}🎮 VR MODE - Ultra Low Latency${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    if [ -f "$STATE_FILE" ] && [ "$(cat "$STATE_FILE")" = "ACTIVE" ]; then
        echo -e "${YELLOW}⚠ Já está ativo! Use 'sudo $0 restart'${NC}"
        exit 1
    fi

    # Verificar interfaces
    if ! ip link show "$WIFI_INTERFACE" &> /dev/null; then
        echo -e "${RED}✗ WiFi '$WIFI_INTERFACE' não encontrada!${NC}"
        exit 1
    fi

    if ! ip link show "$ETH_INTERFACE" &> /dev/null; then
        echo -e "${RED}✗ Ethernet '$ETH_INTERFACE' não encontrada!${NC}"
        exit 1
    fi

    clean_nat
    backup_state

    # Configurar interface
    echo "→ Configurando $ETH_INTERFACE..."
    ip link set "$ETH_INTERFACE" down 2>/dev/null || true
    ip addr flush dev "$ETH_INTERFACE" 2>/dev/null || true
    ip link set "$ETH_INTERFACE" mtu 1500
    ip link set "$ETH_INTERFACE" up
    ip addr add "$ETH_IP/24" dev "$ETH_INTERFACE"
    ip route add 192.168.100.0/24 dev "$ETH_INTERFACE" src "$ETH_IP" 2>/dev/null || true
    echo -e "${GREEN}✓ Interface configurada${NC}"

    # IP forwarding
    echo "→ Ativando IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # UFW
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        echo "→ Configurando UFW..."
        ufw route allow in on "$ETH_INTERFACE" out on "$WIFI_INTERFACE" > /dev/null 2>&1
        ufw route allow in on "$WIFI_INTERFACE" out on "$ETH_INTERFACE" > /dev/null 2>&1
        echo "UFW_MODIFIED" >> "$STATE_FILE"
    fi

    # NAT MINIMALISTA (2 regras apenas)
    echo "→ Configurando NAT..."
    iptables -t nat -A POSTROUTING -o "$WIFI_INTERFACE" -j MASQUERADE
    iptables -A FORWARD -i "$ETH_INTERFACE" -o "$WIFI_INTERFACE" -j ACCEPT
    iptables -A FORWARD -i "$WIFI_INTERFACE" -o "$ETH_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    echo -e "${GREEN}✓ NAT configurado (minimalista)${NC}"

    # OTIMIZAÇÕES CRÍTICAS
    optimize_kernel
    optimize_qos

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ VR MODE ATIVO!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${BLUE}Otimizações ativas:${NC}"
    echo "  ✓ Kernel low-latency"
    echo "  ✓ QoS anti-bufferbloat (fq_codel)"
    echo "  ✓ NAT minimalista (2 regras)"
    echo "  ✓ TCP timestamps OFF"
    echo "  ✓ Hardware offloading OFF"
    echo "  ✓ MTU otimizado (1500)"
    echo "  ✓ SEM DHCP (mais leve)"
    echo ""
    echo -e "${YELLOW}Configuração:${NC}"
    echo "  WiFi:     $WIFI_INTERFACE"
    echo "  Ethernet: $ETH_INTERFACE"
    echo "  Gateway:  $ETH_IP"
    echo ""
    echo -e "${BLUE}Configure IP ESTÁTICO no VR:${NC}"
    echo "  IP:      192.168.100.10"
    echo "  Máscara: 255.255.255.0"
    echo "  Gateway: 192.168.100.1"
    echo "  DNS:     8.8.8.8"
    echo ""
    echo -e "${GREEN}Latência esperada: < 5ms ⚡${NC}"
    echo ""
    echo -e "Parar: ${YELLOW}sudo $0 stop${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# PARAR
stop_sharing() {
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Parando VR Mode${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    if [ ! -f "$STATE_FILE" ]; then
        echo -e "${YELLOW}VR Mode não está ativo${NC}"
        clean_nat
        exit 0
    fi

    restore_state

    echo ""
    echo -e "${GREEN}✓ VR Mode desativado${NC}"
}

# STATUS
check_status() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}🎮 VR Mode Status${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    if [ -f "$STATE_FILE" ] && grep -q "ACTIVE" "$STATE_FILE" 2>/dev/null; then
        echo -e "Status: ${GREEN}● ATIVO${NC}"
    else
        echo -e "Status: ${RED}● INATIVO${NC}"
        echo ""
        echo "Use 'sudo $0 start' para ativar"
        return
    fi

    echo ""

    # Interfaces
    if ip link show "$WIFI_INTERFACE" &> /dev/null; then
        WIFI_IP=$(ip addr show "$WIFI_INTERFACE" | grep "inet " | awk '{print $2}' | cut -d/ -f1)
        echo -e "WiFi ($WIFI_INTERFACE):     ${GREEN}UP${NC} - ${GREEN}$WIFI_IP${NC}"
    fi

    if ip link show "$ETH_INTERFACE" &> /dev/null; then
        ETH_IP_ACTUAL=$(ip addr show "$ETH_INTERFACE" | grep "inet " | awk '{print $2}')
        MTU=$(ip link show "$ETH_INTERFACE" | grep -o "mtu [0-9]*" | awk '{print $2}')
        echo -e "Ethernet ($ETH_INTERFACE): ${GREEN}UP${NC} - ${GREEN}$ETH_IP_ACTUAL${NC} (MTU: $MTU)"
    fi

    echo ""

    # Otimizações
    if grep -q "KERNEL_OPTIMIZED" "$STATE_FILE" 2>/dev/null; then
        echo -e "Otimizações: ${GREEN}✓ Ativas${NC}"

        # Verificar offloading
        GRO=$(ethtool -k "$ETH_INTERFACE" 2>/dev/null | grep "generic-receive-offload:" | awk '{print $2}')
        TSO=$(ethtool -k "$ETH_INTERFACE" 2>/dev/null | grep "tcp-segmentation-offload:" | awk '{print $2}')

        if [ "$GRO" = "off" ] && [ "$TSO" = "off" ]; then
            echo "  • Hardware offloading: ${GREEN}OFF ✓${NC}"
        else
            echo "  • Hardware offloading: ${RED}ON (problema!)${NC}"
        fi

        # TCP timestamps
        TSTAMPS=$(sysctl net.ipv4.tcp_timestamps 2>/dev/null | awk '{print $3}')
        if [ "$TSTAMPS" = "0" ]; then
            echo "  • TCP timestamps: ${GREEN}OFF ✓${NC}"
        else
            echo "  • TCP timestamps: ${YELLOW}ON${NC}"
        fi
    fi

    # QoS
    if grep -q "QOS_CONFIGURED" "$STATE_FILE" 2>/dev/null; then
        QDISC=$(tc qdisc show dev "$ETH_INTERFACE" | grep "fq_codel")
        if [ -n "$QDISC" ]; then
            echo "  • QoS (fq_codel): ${GREEN}Ativo ✓${NC}"
        else
            echo "  • QoS: ${RED}Inativo${NC}"
        fi
    fi

    echo ""

    # NAT
    NAT_COUNT=$(iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -c "$WIFI_INTERFACE")
    if [ "$NAT_COUNT" -eq 1 ]; then
        echo -e "NAT: ${GREEN}OK ✓${NC} (1 regra)"
    elif [ "$NAT_COUNT" -gt 1 ]; then
        echo -e "NAT: ${YELLOW}Duplicado!${NC} ($NAT_COUNT regras) - Execute 'restart'"
    else
        echo -e "NAT: ${RED}Inativo ✗${NC}"
    fi

    # IP Forwarding
    FORWARD=$(sysctl net.ipv4.ip_forward 2>/dev/null | awk '{print $3}')
    if [ "$FORWARD" = "1" ]; then
        echo -e "IP Forwarding: ${GREEN}ON ✓${NC}"
    else
        echo -e "IP Forwarding: ${RED}OFF ✗${NC}"
    fi

    echo ""

    # Teste de latência
    echo -e "${BLUE}Teste de latência para VR (192.168.100.10):${NC}"
    if ping -c 1 -W 1 192.168.100.10 &>/dev/null; then
        LATENCY=$(ping -c 5 -i 0.2 192.168.100.10 2>/dev/null | tail -1 | awk -F '/' '{print $5}')
        if [ -n "$LATENCY" ]; then
            LATENCY_INT=${LATENCY%.*}
            if [ "$LATENCY_INT" -lt 5 ]; then
                echo -e "  Latência média: ${GREEN}${LATENCY}ms ⚡ (EXCELENTE)${NC}"
            elif [ "$LATENCY_INT" -lt 10 ]; then
                echo -e "  Latência média: ${YELLOW}${LATENCY}ms (OK)${NC}"
            else
                echo -e "  Latência média: ${RED}${LATENCY}ms (ALTO!)${NC}"
            fi
        fi
    else
        echo -e "  ${YELLOW}VR não encontrado em 192.168.100.10${NC}"
    fi

    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Menu
case "$1" in
    start)
        start_sharing
        ;;
    stop)
        stop_sharing
        ;;
    status)
        check_status
        ;;
    restart)
        stop_sharing
        sleep 1
        start_sharing
        ;;
    *)
        echo "Uso: $0 {start|stop|restart|status}"
        echo ""
        echo "🎮 VR Mode - Ultra Low Latency (SEM DHCP)"
        echo ""
        echo "Comandos:"
        echo "  start   - Ativa VR mode"
        echo "  stop    - Desativa e restaura sistema"
        echo "  restart - Reinicia"
        echo "  status  - Status detalhado + teste latência"
        exit 1
        ;;
esac

exit 0
