# credcheck

Small zsh function for checking one username and password against common services with NetExec.

## Install

make sure you have Netexec
nxc --version

If it is missing:
sudo apt update && 
sudo apt install netexec

To load it automatically in new terminals:

```zsh
echo 'source /full/path/to/credcheck.zsh' >> ~/.zshrc
source ~/.zshrc
```

## Run

Use targets, username, and password:

```zsh
credcheck "192.168.111.123" "username" "password"
```

Or set targets first:

```zsh
export TARGETS="192.168.111.123"
credcheck "username" "password"
```

Logs and a summary are saved in `./nxc/`.

Only use this on systems you own or are authorized to assess.
