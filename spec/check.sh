#!/usr/bin/env bash
# Model-checks every configuration in spec/ with TLC and compares the outcome with the one
# expected: the agent-vault configurations must hold, the doppler-nix ones must fail on the
# named property. Needs Java 11+; downloads tla2tools.jar (pinned, checked) on first use.
#
#   spec/check.sh            all configurations
#   spec/check.sh LockSteal  only those whose name starts with LockSteal
set -euo pipefail
cd "$(dirname "$0")"

version=1.8.0
sha256=18e0d9caa517a6553ef50c7105191b1bfcfe5cc630bdbceefc087093e0520ce3
jar=tools/tla2tools.jar
if [[ ! -f $jar ]]; then
  mkdir -p tools
  curl -fsSL -o "$jar.part" "https://github.com/tlaplus/tlaplus/releases/download/v$version/tla2tools.jar"
  mv "$jar.part" "$jar"
fi
echo "$sha256  $jar" | sha256sum -c --quiet -

# config  module  expected: "ok" or the property TLC must report violated
checks=(
  "LockSteal            MCLockSteal       ok"
  "LockStealNaive       MCLockSteal       MutualExclusion"
  "LockStealToolSteals  MCLockSteal       MutualExclusion"
  "AgentVaultSync       MCAgentVaultSync  ok"
  "AgentVaultSyncLogout MCAgentVaultSync  ok"
  "DopplerNixBlindWrites MCAgentVaultSync NoLostRefresh|SafeRemoval|Converged"
  "DopplerNixOldBase    MCAgentVaultSync  NoResurrection"
  "DopplerNixBasePerRun MCAgentVaultSync  NoResurrection"
  "DopplerNix           MCAgentVaultSync  NoLostRefresh|SafeRemoval|Converged|NoResurrection"
)

failed=0
for check in "${checks[@]}"; do
  read -r config module expected <<<"$check"
  [[ $config == "${1:-}"* ]] || continue
  log=$(mktemp)
  start=$SECONDS
  java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers auto -deadlock -cleanup \
    -config "$config.cfg" -metadir "states/$config" "$module.tla" >"$log" 2>&1 || true
  took=$((SECONDS - start))
  states=$(grep -oE '[0-9,]+ distinct states found' "$log" | tail -n 1 || true)
  violated=$(grep -oE 'Invariant [A-Za-z]+ is violated' "$log" | head -n 1 | awk '{print $2}' || true)
  if [[ $expected == ok ]] && grep -q 'No error has been found' "$log"; then
    echo "ok    $config: holds ($states, ${took}s)"
  elif [[ $expected != ok && -n $violated && $violated =~ ^($expected)$ ]]; then
    echo "ok    $config: $violated violated, as expected (${took}s)"
  else
    echo "FAIL  $config: expected $expected"
    grep -v '^Picked up' "$log" | tail -n 40
    failed=$((failed + 1))
  fi
  rm -f "$log"
done
rm -rf states
if ((failed)); then
  echo "$failed failed"
  exit 1
fi
