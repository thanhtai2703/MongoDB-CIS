all:
  children:
    web_servers:
      hosts:
%{ for name, h in hosts ~}
%{ if h.role == "web" ~}
        ${name}:
          ansible_host: ${h.ip}
%{ endif ~}
%{ endfor ~}

    database_nodes:
      hosts:
%{ for name, h in hosts ~}
%{ if h.role == "db" ~}
        ${name}:
          ansible_host: ${h.ip}
          mongo_role: ${name == "db-node-1" ? "primary" : "secondary"}
%{ endif ~}
%{ endfor ~}

  vars:
    ansible_user: ${ssh_user}
    ansible_ssh_common_args: "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    mongodb_version: "6.0"
