echo "Proxy ..."
iptables -t nat -S POSTROUTING

whitelist=$(ipset list whitelist | sed -n '/Members/,$p' | tail -n +2 | tr '\n' ' ')
if [ -n "$whitelist" ]; then
    echo "Whitelist: $whitelist"
else
    blacklist=$(ipset list blacklist | sed -n '/Members/,$p' | tail -n +2 | tr '\n' ' ')
    if [ -n "$blacklist" ]; then
        echo "Blacklist: $blacklist"
    fi
fi

echo "Reverse proxy ..."
iptables -t nat -S PREROUTING
