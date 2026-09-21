#!/usr/bin/env bash
set -euo pipefail

action_path="${MENDPACT_ACTION_PATH:?MENDPACT_ACTION_PATH is required}"
mode="${MENDPACT_MODE:-scan}"
driver="${MENDPACT_DRIVER:-replay}"
install_target="${action_path}"

if [[ "${mode}" == "evaluate" ]]; then
  case "${driver}" in
    replay) ;;
    openai|anthropic|gemini)
      install_target="${action_path}[${driver}]"
      ;;
    *)
      echo "MendPact Action: evaluate driver must be 'replay', 'openai', 'anthropic', or 'gemini'." >&2
      exit 2
      ;;
  esac
fi

exec python -m pip install "${install_target}"
