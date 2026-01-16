#!/bin/bash

# Script para compartilhar conexão WiFi via Ethernet
# Uso: ./share-wifi.sh [start|stop|status]

# CONFIGURAÇÕES - AJUSTE AQUI
WIFI_INTERFACE="wlan0"      # Interface WiFi
ETH_INTERFACE="enp6s0"      # Interface Ethernet
ETH_IP="192.168.100.1"      # IP da interface ethernet
ETH_SUBNET="192.168.100.0/24"

# Arquivos de backup e controle
BACKUP_DIR="/tmp/wifi-share-backup"
IPTABLES_BACKUP="$BACKUP_DIR/iptables-rules.bak"
SYSCTL_BACKUP="$BACKUP_DIR/sysctl.bak"
STATE_FILE="$BACKUP_DIR/state"
DNSMASQ_PID="$BACKUP_DIR/dnsmasq.pid"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Verifica se é root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Este script precisa ser executado como root (use sudo)${NC}"
    exit 1
fi

# Cria diretório de backup
mkdir -p "$BACKUP_DIR"

# Função para limpar regras NAT duplicadas e antigas
clean_old_nat_rules() {
    echo "Limpando regras NAT antigas..."

    # Limpa regras nftables se existirem
    nft delete rule ip nat POSTROUTING handle $(nft -a list table ip nat | grep "oifname \"$WIFI_INTERFACE\" masquerade" | awk '{print $NF}') 2>/dev/null || true

    # Remove todas as regras relacionadas ao nosso setup (iptables legacy)
    while iptables -t nat -C POSTROUTING -o "$WIFI_INTERFACE" -j MASQUERADE 2>/dev/null; do
        iptables -t nat -D POSTROUTING -o "$WIFI_INTERFACE" -j MASQUERADE 2>/dev/null
    done

    while iptables -C FORWARD -i "$WIFI_INTERFACE" -o "$ETH_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do
        iptables -D FORWARD -i "$WIFI_INTERFACE" -o "$ETH_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    done

    while iptables -C FORWARD -i "$ETH_INTERFACE" -o "$WIFI_INTERFACE" -j ACCEPT 2>/dev/null; do
        iptables -D FORWARD -i "$ETH_INTERFACE" -o "$WIFI_INTERFACE" -j ACCEPT 2>/dev/null
    done
}

# Função para salvar estado atual do sistema
backup_system_state() {
    echo "Salvando estado atual do sistema..."

    # Salva regras do iptables (antes de qualquer modificação)
    iptables-save > "$IPTABLES_BACKUP"

    # Salva estado do IP forwarding (só salva se não estiver ativo já)
    CURRENT_FORWARD=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
    if [ "$CURRENT_FORWARD" = "0" ]; then
        echo "0" > "$SYSCTL_BACKUP"
    else
        # Se já está ativo, assume que deve ficar ativo
        echo "1" > "$SYSCTL_BACKUP"
    fi

    # Salva configuração da interface ethernet
    ip addr show "$ETH_INTERFACE" > "$BACKUP_DIR/eth-config.bak" 2>/dev/null || true

    # Marca que o sistema foi modificado
    echo "ACTIVE" > "$STATE_FILE"
}

# Função para restaurar estado original do sistema
restore_system_state() {
    echo "Restaurando estado original do sistema..."

    if [ ! -f "$STATE_FILE" ]; then
        echo -e "${YELLOW}Nenhum backup encontrado. Sistema já estava limpo.${NC}"
        return
    fi

    # Limpa regras NAT criadas pelo script
    clean_old_nat_rules

    # Restaura regras do iptables completamente
    if [ -f "$IPTABLES_BACKUP" ]; then
        echo "Restaurando regras do iptables..."
        iptables-restore < "$IPTABLES_BACKUP"
    fi

    # Restaura IP forwarding
    if [ -f "$SYSCTL_BACKUP" ]; then
        OLD_FORWARD=$(cat "$SYSCTL_BACKUP")
        echo "Restaurando IP forwarding para: $OLD_FORWARD"
        sysctl -w net.ipv4.ip_forward="$OLD_FORWARD" > /dev/null
    else
        # Se não tem backup, desativa por segurança
        echo "Desativando IP forwarding (sem backup encontrado)..."
        sysctl -w net.ipv4.ip_forward=0 > /dev/null
    fi

    # Remove regras do UFW se foram adicionadas
    if grep -q "UFW_MODIFIED" "$STATE_FILE" 2>/dev/null; then
        echo "Removendo regras do UFW..."
        if command -v ufw &> /dev/null; then
            ufw route delete allow in on "$ETH_INTERFACE" out on "$WIFI_INTERFACE" 2>/dev/null || true
            ufw route delete allow in on "$WIFI_INTERFACE" out on "$ETH_INTERFACE" 2>/dev/null || true
        fi
    fi

    # Limpa interface ethernet completamente
    echo "Limpando interface $ETH_INTERFACE..."
    ip addr flush dev "$ETH_INTERFACE" 2>/dev/null || true
    ip link set "$ETH_INTERFACE" down 2>/dev/null || true

    # Para e remove dnsmasq
    if [ -f "$DNSMASQ_PID" ]; then
        DPID=$(cat "$DNSMASQ_PID")
        if kill -0 "$DPID" 2>/dev/null; then
            echo "Parando servidor DHCP..."
            kill "$DPID" 2>/dev/null || true
            sleep 1
            kill -9 "$DPID" 2>/dev/null || true
        fi
        rm -f "$DNSMASQ_PID"
    fi

    # Reinicia dnsmasq do sistema se foi parado
    if grep -q "SYSTEM_DNSMASQ_STOPPED" "$STATE_FILE" 2>/dev/null; then
        echo "Reiniciando dnsmasq do sistema..."
        systemctl start dnsmasq 2>/dev/null || true
    fi

    # Remove arquivos temporários
    rm -f /tmp/dnsmasq-share.conf

    # Remove backup
    rm -rf "$BACKUP_DIR"

    echo -e "${GREEN}Estado original do sistema restaurado completamente!${NC}"
}

# Função para iniciar compartilhamento
start_sharing() {
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Iniciando compartilhamento de rede${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Verifica se já está rodando
    if [ -f "$STATE_FILE" ] && [ "$(cat "$STATE_FILE")" = "ACTIVE" ]; then
        echo -e "${YELLOW}⚠ Compartilhamento já está ativo!${NC}"
        echo -e "${YELLOW}Use '$0 stop' para parar primeiro ou '$0 restart' para reiniciar.${NC}"
        exit 1
    fi

    # Limpa qualquer resquício de execuções anteriores
    echo "Verificando resquícios de configurações antigas..."
    clean_old_nat_rules

    # Verifica se as interfaces existem
    if ! ip link show "$WIFI_INTERFACE" &> /dev/null; then
        echo -e "${RED}✗ Interface WiFi '$WIFI_INTERFACE' não encontrada!${NC}"
        echo "Interfaces disponíveis:"
        ip link show | grep "^[0-9]" | awk '{print $2}' | sed 's/://'
        exit 1
    fi

    if ! ip link show "$ETH_INTERFACE" &> /dev/null; then
        echo -e "${RED}✗ Interface Ethernet '$ETH_INTERFACE' não encontrada!${NC}"
        echo "Interfaces disponíveis:"
        ip link show | grep "^[0-9]" | awk '{print $2}' | sed 's/://'
        exit 1
    fi

    # Verifica se WiFi está conectado
    if ! ip addr show "$WIFI_INTERFACE" | grep -q "inet "; then
        echo -e "${YELLOW}⚠ Aviso: Interface WiFi parece não estar conectada!${NC}"
        read -p "Deseja continuar mesmo assim? (s/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Ss]$ ]]; then
            exit 1
        fi
    fi

    # Salva estado atual antes de fazer alterações
    backup_system_state

    # Configura IP da interface ethernet
    echo "→ Configurando $ETH_INTERFACE com IP $ETH_IP..."
    ip link set "$ETH_INTERFACE" up
    # Remove qualquer IP existente antes de adicionar
    ip addr flush dev "$ETH_INTERFACE" 2>/dev/null || true
    ip addr add "$ETH_IP/24" dev "$ETH_INTERFACE"

    # Adiciona rota para a rede 192.168.100.0/24
    echo "→ Configurando rotas de rede..."
    ip route add 192.168.100.0/24 dev "$ETH_INTERFACE" src "$ETH_IP" 2>/dev/null || true
    echo -e "${GREEN}✓ PC agora tem acesso à rede 192.168.100.x${NC}"

    # Habilita IP forwarding
    echo "→ Habilitando IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # Configura UFW para permitir forwarding
    echo "→ Configurando UFW..."

    # Verifica se UFW está ativo
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        echo "  UFW detectado, configurando regras..."

        # Permite forwarding entre as interfaces
        ufw route allow in on "$ETH_INTERFACE" out on "$WIFI_INTERFACE"
        ufw route allow in on "$WIFI_INTERFACE" out on "$ETH_INTERFACE"

        # Salva que UFW foi modificado
        echo "UFW_MODIFIED" >> "$STATE_FILE"
    fi

    # Configura NAT com iptables (APENAS UMA VEZ)
    echo "→ Configurando NAT (iptables)..."

    # Usa nft (nftables) já que UFW usa iptables-nft
    nft add rule ip nat POSTROUTING oifname "$WIFI_INTERFACE" masquerade
    nft add rule ip filter FORWARD iifname "$ETH_INTERFACE" oifname "$WIFI_INTERFACE" accept
    nft add rule ip filter FORWARD iifname "$WIFI_INTERFACE" oifname "$ETH_INTERFACE" ct state related,established accept

    # Verifica se as regras foram aplicadas
    sleep 1
    if nft list table ip nat | grep -q "masquerade"; then
        echo -e "${GREEN}✓ Regras NAT aplicadas com sucesso!${NC}"
    else
        echo -e "${RED}✗ ERRO: Falha ao configurar regras NAT!${NC}"
        restore_system_state
        exit 1
    fi

    # Inicia dnsmasq para DHCP (opcional - pode não funcionar com todos os roteadores bridge)
    if command -v dnsmasq &> /dev/null; then
        echo "→ Configurando servidor DHCP (experimental)..."

        # Para o dnsmasq do sistema se estiver rodando
        if systemctl is-active --quiet dnsmasq; then
            echo "  Parando dnsmasq do sistema..."
            systemctl stop dnsmasq 2>/dev/null
            echo "SYSTEM_DNSMASQ_STOPPED" >> "$STATE_FILE"
        fi

        # Cria config temporária (sem DNS server, só DHCP)
        cat > /tmp/dnsmasq-share.conf << EOF
interface=$ETH_INTERFACE
bind-interfaces
except-interface=lo
port=0
dhcp-range=192.168.100.50,192.168.100.150,12h
dhcp-option=3,$ETH_IP
dhcp-option=6,8.8.8.8,8.8.4.4
no-resolv
no-poll
pid-file=$DNSMASQ_PID
log-dhcp
EOF
        # Inicia dnsmasq em background
        dnsmasq -C /tmp/dnsmasq-share.conf 2>/dev/null &
        DNSMASQ_NEW_PID=$!
        echo $DNSMASQ_NEW_PID > "$DNSMASQ_PID"
        sleep 1

        if [ -f "$DNSMASQ_PID" ] && kill -0 $(cat "$DNSMASQ_PID") 2>/dev/null; then
            echo -e "${GREEN}✓ Servidor DHCP iniciado (PID: $(cat "$DNSMASQ_PID"))${NC}"
            echo -e "${YELLOW}  Nota: Muitos roteadores bridge bloqueiam DHCP${NC}"
        else
            echo -e "${YELLOW}⚠ DHCP não iniciado - use configuração manual de IP${NC}"
        fi
    fi

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ Compartilhamento de rede ATIVADO!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${BLUE}Configuração:${NC}"
    echo -e "  WiFi (origem):    ${GREEN}$WIFI_INTERFACE${NC}"
    echo -e "  Ethernet (saída): ${GREEN}$ETH_INTERFACE${NC}"
    echo -e "  IP do PC:         ${GREEN}$ETH_IP${NC}"
    echo -e "  Rede local:       ${GREEN}192.168.100.0/24${NC}"
    echo ""
    echo -e "${BLUE}Como configurar dispositivos:${NC}"
    echo -e "${YELLOW}  IMPORTANTE: Configure IP MANUAL nos dispositivos!${NC}"
    echo ""
    echo -e "  ${GREEN}Configuração recomendada:${NC}"
    echo -e "    IP:      192.168.100.10 (ou .11, .12, etc até .254)"
    echo -e "    Máscara: 255.255.255.0"
    echo -e "    Gateway: 192.168.100.1"
    echo -e "    DNS:     8.8.8.8 e 8.8.4.4"
    echo ""
    echo -e "  ${BLUE}Acesso do PC à rede local:${NC}"
    echo -e "    Seu PC está em ${GREEN}192.168.100.1${NC}"
    echo -e "    Você pode acessar dispositivos como: ${GREEN}192.168.100.10${NC}"
    echo -e "    Exemplo VR: ${GREEN}ping 192.168.100.10${NC} ou ${GREEN}http://192.168.100.10${NC}"
    echo ""
    echo -e "  ${YELLOW}Nota: DHCP geralmente não funciona com roteadores bridge${NC}"
    echo ""
    echo -e "Para parar: ${YELLOW}sudo $0 stop${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Função para parar compartilhamento
stop_sharing() {
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Parando compartilhamento de rede${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    if [ ! -f "$STATE_FILE" ]; then
        echo -e "${YELLOW}Compartilhamento não está ativo.${NC}"
        echo "Executando limpeza de segurança..."
        clean_old_nat_rules
        exit 0
    fi

    # Restaura tudo ao estado original
    restore_system_state

    echo ""
    echo -e "${GREEN}✓ Compartilhamento DESATIVADO e sistema restaurado!${NC}"
}

# Função para verificar status
check_status() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Status do compartilhamento de rede${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Verifica se está ativo
    if [ -f "$STATE_FILE" ] && [ "$(cat "$STATE_FILE")" = "ACTIVE" ]; then
        echo -e "Estado: ${GREEN}● ATIVO${NC}"
    else
        echo -e "Estado: ${RED}● INATIVO${NC}"
        echo ""
        echo "Use '$0 start' para iniciar o compartilhamento"
        return
    fi

    echo ""

    # Verifica interfaces
    echo -e "${BLUE}Interfaces:${NC}"
    if ip link show "$WIFI_INTERFACE" &> /dev/null; then
        WIFI_STATE=$(ip link show "$WIFI_INTERFACE" | grep -o "state [A-Z]*" | awk '{print $2}')
        WIFI_IP=$(ip addr show "$WIFI_INTERFACE" | grep "inet " | awk '{print $2}' | cut -d/ -f1)
        if [ "$WIFI_STATE" = "UP" ]; then
            echo -e "  WiFi ($WIFI_INTERFACE):     ${GREEN}$WIFI_STATE${NC} - IP: ${GREEN}${WIFI_IP:-N/A}${NC}"
        else
            echo -e "  WiFi ($WIFI_INTERFACE):     ${YELLOW}$WIFI_STATE${NC} - IP: ${YELLOW}${WIFI_IP:-N/A}${NC}"
        fi
    else
        echo -e "  WiFi ($WIFI_INTERFACE):     ${RED}NÃO ENCONTRADA${NC}"
    fi

    if ip link show "$ETH_INTERFACE" &> /dev/null; then
        ETH_STATE=$(ip link show "$ETH_INTERFACE" | grep -o "state [A-Z]*" | awk '{print $2}')
        ETH_IP_ACTUAL=$(ip addr show "$ETH_INTERFACE" | grep "inet " | awk '{print $2}')
        if [ "$ETH_STATE" = "UP" ]; then
            echo -e "  Ethernet ($ETH_INTERFACE): ${GREEN}$ETH_STATE${NC} - IP: ${GREEN}${ETH_IP_ACTUAL:-N/A}${NC}"
        else
            echo -e "  Ethernet ($ETH_INTERFACE): ${YELLOW}$ETH_STATE${NC} - IP: ${YELLOW}${ETH_IP_ACTUAL:-N/A}${NC}"
        fi
    else
        echo -e "  Ethernet ($ETH_INTERFACE): ${RED}NÃO ENCONTRADA${NC}"
    fi

    echo ""

    # Verifica rotas
    if ip route | grep -q "192.168.100.0/24"; then
        echo -e "Rota local (192.168.100.0/24): ${GREEN}Configurada ✓${NC}"
        ROUTE_INFO=$(ip route | grep "192.168.100.0/24")
        echo -e "  $ROUTE_INFO"
    else
        echo -e "Rota local: ${RED}Não configurada ✗${NC}"
    fi

    echo ""

    # Verifica IP forwarding
    FORWARD=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
    if [ "$FORWARD" = "1" ]; then
        echo -e "IP Forwarding: ${GREEN}Ativado ✓${NC}"
    else
        echo -e "IP Forwarding: ${RED}Desativado ✗${NC}"
    fi

    # Verifica regras iptables/nftables
    NAT_ACTIVE=false

    # Verifica se tem regras via nftables
    if nft list table ip nat 2>/dev/null | grep -q "masquerade"; then
        echo -e "Regras NAT: ${GREEN}Ativas ✓${NC} (via nftables)"
        NAT_ACTIVE=true
    else
        # Verifica via iptables
        NAT_COUNT=$(iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -c "$WIFI_INTERFACE")
        FORWARD_COUNT=$(iptables -L FORWARD -n 2>/dev/null | grep -c "$ETH_INTERFACE\|$WIFI_INTERFACE")

        if [ "$NAT_COUNT" -gt 0 ]; then
            if [ "$NAT_COUNT" -eq 1 ]; then
                echo -e "Regras NAT: ${GREEN}Ativas ✓${NC} (POSTROUTING: $NAT_COUNT, FORWARD: $FORWARD_COUNT)"
            else
                echo -e "Regras NAT: ${YELLOW}Ativas (DUPLICADAS!)${NC} (POSTROUTING: $NAT_COUNT, FORWARD: $FORWARD_COUNT)"
                echo -e "  ${YELLOW}⚠ Execute 'sudo $0 restart' para limpar duplicatas${NC}"
            fi
            NAT_ACTIVE=true
        else
            echo -e "Regras NAT: ${RED}Inativas ✗${NC}"
            echo -e "  ${YELLOW}Execute 'sudo $0 restart' para recriar as regras${NC}"
        fi
    fi

    # Verifica dnsmasq
    if [ -f "$DNSMASQ_PID" ] && kill -0 $(cat "$DNSMASQ_PID") 2>/dev/null; then
        echo -e "Servidor DHCP: ${GREEN}Rodando ✓${NC} (PID: $(cat "$DNSMASQ_PID"))"

        # Mostra logs recentes se disponível
        if [ -f "/var/log/dnsmasq.log" ]; then
            RECENT_LEASES=$(tail -n 5 /var/log/dnsmasq.log 2>/dev/null | grep -c "DHCPACK")
            if [ "$RECENT_LEASES" -gt 0 ]; then
                echo -e "  ${GREEN}Últimos IPs atribuídos: $RECENT_LEASES${NC}"
            fi
        fi
    else
        echo -e "Servidor DHCP: ${RED}Parado ✗${NC}"
    fi

    echo ""

    # Diagnóstico
    if [ "$NAT_ACTIVE" = true ] && [ "$FORWARD" = "1" ]; then
        echo -e "${GREEN}✓ Sistema funcionando corretamente!${NC}"
    else
        echo -e "${RED}⚠ Problemas detectados - execute 'sudo $0 restart'${NC}"
    fi

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Função para limpeza forçada
force_clean() {
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}Executando limpeza forçada do sistema${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Limpa todas as regras NAT relacionadas
    echo "→ Limpando regras iptables..."
    clean_old_nat_rules

    # Para todos os dnsmasq relacionados
    echo "→ Parando processos dnsmasq..."
    if [ -f "$DNSMASQ_PID" ]; then
        kill $(cat "$DNSMASQ_PID") 2>/dev/null || true
    fi
    killall dnsmasq 2>/dev/null || true

    # Limpa interface ethernet
    echo "→ Limpando interface $ETH_INTERFACE..."
    ip addr flush dev "$ETH_INTERFACE" 2>/dev/null || true
    ip link set "$ETH_INTERFACE" down 2>/dev/null || true

    # Remove arquivos temporários
    echo "→ Removendo arquivos temporários..."
    rm -rf "$BACKUP_DIR"
    rm -f /tmp/dnsmasq-share.conf

    echo ""
    echo -e "${GREEN}✓ Limpeza forçada concluída!${NC}"
    echo -e "${YELLOW}Nota: IP forwarding não foi alterado por segurança.${NC}"
}

# Menu principal
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
        echo ""
        sleep 2
        start_sharing
        ;;
    clean|force-clean)
        force_clean
        ;;
    *)
        echo "Uso: $0 {start|stop|restart|status|force-clean}"
        echo ""
        echo "Comandos:"
        echo "  start       - Inicia o compartilhamento de rede"
        echo "  stop        - Para e restaura o sistema ao estado original"
        echo "  restart     - Reinicia o compartilhamento (limpa duplicatas)"
        echo "  status      - Mostra o status detalhado"
        echo "  force-clean - Limpeza forçada (use se algo deu errado)"
        echo ""
        echo "Configuração atual:"
        echo "  WiFi:     $WIFI_INTERFACE"
        echo "  Ethernet: $ETH_INTERFACE"
        echo "  Gateway:  $ETH_IP"
        exit 1
        ;;
esac

exit 0
