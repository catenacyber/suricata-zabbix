#/bin/sh
export RUSTFLAGS=-Clink-args=-Wl,-undefined,dynamic_lookup
cargo fmt
#cargo build  --features suricata7 --no-default-features
cargo clippy --fix --allow-dirty --lib
cargo build
ls pcaps/* | cut -d/ -f2- | while read i ; do
     rm log/eve.json
    ../src/suricata -c ./zabbix.yaml -S zabbix.rules -k none --runmode single -l log -r pcaps/$i
    jq 'select(.event_type != "flow")' log/eve.json | grep -v flow_id > output/$i.json
done
