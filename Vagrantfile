Vagrant.configure("2") do |config|
  config.vm.provider "docker" do |d|
    d.image = "ubuntu:18.04"
    d.remains_running = true
    d.has_ssh = true
    d.name = "boxguard-test"
    d.ports = ["2222:22"]
    d.cmd = ["tail", "-f", "/dev/null"]  # keep container running
  end

  config.ssh.username = "root"
  config.ssh.password = "root"

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y openssh-server

    mkdir -p /var/run/sshd
    echo 'root:root' | chpasswd
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

    /usr/sbin/sshd

    # Install pinned packages for CVE regression testing
    apt-get install -y openssl=1.1.0g-2ubuntu4 sudo=1.8.21p2-3ubuntu1.2 policykit-1=0.105-20ubuntu0.18.04.6

    apt-mark hold openssl sudo policykit-1

    echo "Pinned test packages installed."
  SHELL
end
