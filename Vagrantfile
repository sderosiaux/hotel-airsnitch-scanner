# -*- mode: ruby -*-
# Vagrant VM for mac80211_hwsim integration testing.
# Usage: vagrant up && vagrant ssh -c 'cd /vagrant && uv run pytest tests/hwsim/ -m hwsim -v'

Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-24.04"  # Ubuntu 24.04 LTS (ARM64 compatible)
  config.vm.hostname = "airsnitch-hwsim"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
    vb.name = "airsnitch-hwsim"
  end

  # Mount project root
  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  # Provision: install dependencies, kernel headers, setup hwsim
  config.vm.provision "shell", inline: <<-SHELL
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    # System packages
    apt-get update -qq
    apt-get install -y -qq \
      hostapd \
      wpasupplicant \
      iw \
      wireless-tools \
      python3 \
      python3-venv \
      python3-pip \
      linux-headers-$(uname -r) \
      build-essential \
      curl \
      git

    # Install uv
    if ! command -v uv &>/dev/null; then
      curl -LsSf https://astral.sh/uv/install.sh | sh
      echo 'export PATH="$HOME/.local/bin:$PATH"' >> /etc/profile.d/uv.sh
    fi
    export PATH="/root/.local/bin:$PATH"

    # Ensure mac80211_hwsim is available
    if ! modprobe --dry-run mac80211_hwsim 2>/dev/null; then
      echo "WARNING: mac80211_hwsim not available in this kernel"
      echo "You may need: apt install linux-modules-extra-$(uname -r)"
      apt-get install -y -qq "linux-modules-extra-$(uname -r)" || true
    fi

    # Install project dependencies
    cd /vagrant
    uv sync

    echo ""
    echo "=== Provisioning complete ==="
    echo "To run hwsim tests:"
    echo "  vagrant ssh"
    echo "  sudo bash /vagrant/tests/hwsim/setup_hwsim.sh"
    echo "  cd /vagrant && sudo uv run pytest tests/hwsim/ -m hwsim -v"
    echo "  sudo bash /vagrant/tests/hwsim/teardown_hwsim.sh"
  SHELL
end
