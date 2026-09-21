#!/usr/bin/env bash
set -euo pipefail

mode="${MENDPACT_MODE:-scan}"
target="${MENDPACT_TARGET:-}"
source_report="${MENDPACT_SOURCE_REPORT:-}"
output="${MENDPACT_OUTPUT:-mendpact-report.json}"
policy="${MENDPACT_POLICY:-}"
auth_token_env="${MENDPACT_AUTH_TOKEN_ENV:-}"
allow_private="${MENDPACT_ALLOW_PRIVATE:-false}"
allow_insecure_http="${MENDPACT_ALLOW_INSECURE_HTTP:-false}"
allow_new_confusions_input="${MENDPACT_ALLOW_NEW_CONFUSIONS:-}"
allow_new_confusions="${allow_new_confusions_input:-false}"

if [[ -z "${output}" ]]; then
  echo "MendPact Action: output cannot be empty." >&2
  exit 2
fi

validate_boolean() {
  local value="$1"
  local flag="$2"
  case "${value}" in
    true|false) ;;
    *)
      echo "MendPact Action: ${flag} must be 'true' or 'false'." >&2
      exit 2
      ;;
  esac
}

validate_positive_integer() {
  local value="$1"
  local input_name="$2"
  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]]; then
    echo "MendPact Action: ${input_name} must be a positive integer." >&2
    exit 2
  fi
}

append_boolean_flag() {
  local value="$1"
  local flag="$2"
  if [[ "${value}" == "true" ]]; then
    command_args+=("${flag}")
  fi
}

validate_boolean "${allow_private}" --allow-private
validate_boolean "${allow_insecure_http}" --allow-insecure-http
validate_boolean "${allow_new_confusions}" --allow-new-confusions
if [[ -n "${policy}" ]] && \
   [[ "${allow_private}" == "true" || "${allow_insecure_http}" == "true" ]]; then
  echo "MendPact Action: policy cannot be combined with target allowance inputs." >&2
  exit 2
fi
if [[ -n "${policy}" && -n "${auth_token_env}" ]]; then
  echo "MendPact Action: policy cannot be combined with auth-token-env." >&2
  exit 2
fi
if [[ "${mode}" == "auth" && -n "${auth_token_env}" ]]; then
  echo "MendPact Action: auth mode never loads a token; remove auth-token-env." >&2
  exit 2
fi
if [[ "${mode}" != "recheck" && -n "${source_report}" ]]; then
  echo "MendPact Action: source-report can only be used in recheck mode." >&2
  exit 2
fi

case "${mode}" in
  auth)
    if [[ -z "${target}" ]]; then
      echo "MendPact Action: target is required in auth mode." >&2
      exit 2
    fi
    command_args=(
      mendpact auth-check "${target}"
    )
    if [[ -z "${policy}" ]]; then
      command_args+=(--fail-on "${MENDPACT_FAIL_ON:-high}")
    fi
    command_args+=(--output "${output}")
    ;;
  scan)
    if [[ -z "${target}" ]]; then
      echo "MendPact Action: target is required in scan mode." >&2
      exit 2
    fi
    command_args=(
      mendpact scan "${target}"
    )
    if [[ -z "${policy}" ]]; then
      command_args+=(--fail-on "${MENDPACT_FAIL_ON:-high}")
    fi
    command_args+=(--output "${output}")
    ;;
  recheck)
    if [[ -z "${source_report}" ]]; then
      echo "MendPact Action: source-report is required in recheck mode." >&2
      exit 2
    fi
    if [[ -n "${target}" || -n "${auth_token_env}" || \
       "${allow_private}" == "true" || "${allow_insecure_http}" == "true" ]]; then
      echo "MendPact Action: recheck mode is offline and does not accept target, authentication, or target allowance inputs." >&2
      exit 2
    fi
    if [[ -n "${MENDPACT_BASELINE:-}" || -n "${MENDPACT_SCENARIO:-}" || \
       -n "${MENDPACT_REPLAY:-}" || -n "${MENDPACT_SAVE_SCAN:-}" || \
       -n "${MENDPACT_REFERENCE_REPORT:-}" || -n "${MENDPACT_CANDIDATE_REPORT:-}" || \
       -n "${MENDPACT_SEMANTIC_LABELS:-}" ]]; then
      echo "MendPact Action: recheck mode accepts only source-report, output, policy, and fail-on inputs." >&2
      exit 2
    fi
    command_args=(mendpact recheck "${source_report}")
    if [[ -n "${policy}" ]]; then
      command_args+=(--policy "${policy}")
    else
      command_args+=(--fail-on "${MENDPACT_FAIL_ON:-high}")
    fi
    command_args+=(--output "${output}")
    ;;
  evaluate)
    scenario="${MENDPACT_SCENARIO:-}"
    replay="${MENDPACT_REPLAY:-}"
    driver="${MENDPACT_DRIVER:-replay}"
    model="${MENDPACT_MODEL:-}"
    repetitions="${MENDPACT_REPETITIONS:-1}"
    max_trials="${MENDPACT_MAX_TRIALS:-10}"
    if [[ -z "${target}" ]]; then
      echo "MendPact Action: target is required in evaluate mode." >&2
      exit 2
    fi
    if [[ -z "${scenario}" ]]; then
      echo "MendPact Action: scenario is required in evaluate mode." >&2
      exit 2
    fi
    if [[ -n "${policy}" ]]; then
      echo "MendPact Action: evaluate mode does not accept policy; use explicit evaluation inputs." >&2
      exit 2
    fi
    validate_positive_integer "${repetitions}" repetitions
    validate_positive_integer "${max_trials}" max-trials
    case "${driver}" in
      replay)
        if [[ -z "${replay}" ]]; then
          echo "MendPact Action: replay is required with the replay evaluate driver." >&2
          exit 2
        fi
        if [[ -n "${model}" ]]; then
          echo "MendPact Action: model cannot be used with the replay evaluate driver." >&2
          exit 2
        fi
        ;;
      openai|anthropic|gemini)
        if [[ -z "${model}" ]]; then
          echo "MendPact Action: model is required with a live evaluate driver." >&2
          exit 2
        fi
        if [[ -n "${replay}" ]]; then
          echo "MendPact Action: replay cannot be used with a live evaluate driver." >&2
          exit 2
        fi
        ;;
      *)
        echo "MendPact Action: evaluate driver must be 'replay', 'openai', 'anthropic', or 'gemini'." >&2
        exit 2
        ;;
    esac
    command_args=(
      mendpact evaluate "${target}"
      --scenario "${scenario}"
      --driver "${driver}"
      --repetitions "${repetitions}"
      --max-trials "${max_trials}"
      --output "${output}"
    )
    if [[ "${driver}" == "replay" ]]; then
      command_args+=(--replay "${replay}")
    else
      command_args+=(--model "${model}")
    fi
    if [[ -n "${MENDPACT_SAVE_REPLAY:-}" ]]; then
      command_args+=(--save-replay "${MENDPACT_SAVE_REPLAY}")
    fi
    ;;
  guard)
    baseline="${MENDPACT_BASELINE:-}"
    scenario="${MENDPACT_SCENARIO:-}"
    replay="${MENDPACT_REPLAY:-}"
    if [[ -z "${target}" ]]; then
      echo "MendPact Action: target is required in guard mode." >&2
      exit 2
    fi
    if [[ -z "${baseline}" ]]; then
      echo "MendPact Action: baseline is required in guard mode." >&2
      exit 2
    fi
    if [[ -n "${scenario}" && -z "${replay}" ]] || \
       [[ -z "${scenario}" && -n "${replay}" ]]; then
      echo "MendPact Action: scenario and replay must be supplied together." >&2
      exit 2
    fi
    command_args=(
      mendpact guard "${target}"
      --baseline "${baseline}"
      --repetitions "${MENDPACT_REPETITIONS:-1}"
    )
    if [[ -z "${policy}" ]]; then
      command_args+=(
        --scan-fail-on "${MENDPACT_SCAN_FAIL_ON:-high}"
        --contract-fail-on "${MENDPACT_CONTRACT_FAIL_ON:-breaking}"
      )
    fi
    command_args+=(--output "${output}")
    if [[ -n "${scenario}" ]]; then
      command_args+=(--scenario "${scenario}" --replay "${replay}")
    fi
    if [[ -n "${MENDPACT_SAVE_SCAN:-}" ]]; then
      command_args+=(--save-scan "${MENDPACT_SAVE_SCAN}")
    fi
    ;;
  compare-models)
    reference_report="${MENDPACT_REFERENCE_REPORT:-}"
    candidate_report="${MENDPACT_CANDIDATE_REPORT:-}"
    if [[ -z "${reference_report}" || -z "${candidate_report}" ]]; then
      echo "MendPact Action: reference-report and candidate-report are required in compare-models mode." >&2
      exit 2
    fi
    if [[ -n "${target}" || -n "${auth_token_env}" || \
       "${allow_private}" == "true" || "${allow_insecure_http}" == "true" ]]; then
      echo "MendPact Action: compare-models mode does not accept target, authentication, or target allowance inputs." >&2
      exit 2
    fi
    command_args=(
      mendpact compare-models "${reference_report}" "${candidate_report}"
    )
    if [[ -n "${policy}" ]]; then
      if [[ -n "${MENDPACT_MAX_OVERALL_PASS_RATE_DROP:-}" || \
         -n "${MENDPACT_MAX_SCENARIO_PASS_RATE_DROP:-}" || \
         -n "${allow_new_confusions_input}" ]]; then
        echo "MendPact Action: policy cannot be combined with model-comparison threshold inputs." >&2
        exit 2
      fi
      command_args+=(--policy "${policy}")
    else
      command_args+=(
        --max-overall-pass-rate-drop "${MENDPACT_MAX_OVERALL_PASS_RATE_DROP:-0}"
        --max-scenario-pass-rate-drop "${MENDPACT_MAX_SCENARIO_PASS_RATE_DROP:-0}"
      )
    fi
    command_args+=(--output "${output}")
    if [[ -z "${policy}" ]]; then
      append_boolean_flag "${allow_new_confusions}" --allow-new-confusions
    fi
    ;;
  calibrate-grader)
    semantic_labels="${MENDPACT_SEMANTIC_LABELS:-}"
    if [[ -z "${semantic_labels}" ]]; then
      echo "MendPact Action: semantic-labels is required in calibrate-grader mode." >&2
      exit 2
    fi
    if [[ -n "${target}" || -n "${auth_token_env}" || \
       "${allow_private}" == "true" || "${allow_insecure_http}" == "true" ]]; then
      echo "MendPact Action: calibrate-grader mode does not accept target, authentication, or target allowance inputs." >&2
      exit 2
    fi
    command_args=(
      mendpact calibrate-grader "${semantic_labels}"
    )
    if [[ -n "${policy}" ]]; then
      if [[ -n "${MENDPACT_MIN_CALIBRATION_EXAMPLES:-}" || \
         -n "${MENDPACT_MIN_VALIDATION_EXAMPLES:-}" || \
         -n "${MENDPACT_MIN_VALIDATION_BALANCED_ACCURACY:-}" || \
         -n "${MENDPACT_MAX_VALIDATION_FALSE_ACCEPT_RATE:-}" ]]; then
        echo "MendPact Action: policy cannot be combined with semantic-calibration threshold inputs." >&2
        exit 2
      fi
      command_args+=(--policy "${policy}")
    else
      command_args+=(
        --min-calibration-examples "${MENDPACT_MIN_CALIBRATION_EXAMPLES:-4}"
        --min-validation-examples "${MENDPACT_MIN_VALIDATION_EXAMPLES:-4}"
        --min-validation-balanced-accuracy "${MENDPACT_MIN_VALIDATION_BALANCED_ACCURACY:-0.8}"
        --max-validation-false-accept-rate "${MENDPACT_MAX_VALIDATION_FALSE_ACCEPT_RATE:-0.1}"
      )
    fi
    command_args+=(--output "${output}")
    ;;
  *)
    echo "MendPact Action: mode must be 'auth', 'scan', 'recheck', 'evaluate', 'guard', 'compare-models', or 'calibrate-grader'." >&2
    exit 2
    ;;
esac

if [[ "${mode}" == "auth" || "${mode}" == "scan" || "${mode}" == "evaluate" || \
      "${mode}" == "guard" ]]; then
  if [[ -n "${policy}" ]]; then
    command_args+=(--policy "${policy}")
  else
    if [[ -n "${auth_token_env}" ]]; then
      command_args+=(--auth-token-env "${auth_token_env}")
    fi
    append_boolean_flag "${allow_private}" --allow-private
    append_boolean_flag "${allow_insecure_http}" --allow-insecure-http
  fi
fi

exec "${command_args[@]}"
