# Validación de disponibilidad — gcob 0.5.4

Fecha: 2026-09-12. Working tree sobre el commit `55ef1ef`.
Entorno: Linux, `rustc 1.97.1`, `cargo 1.97.1`, `cargo-deny 0.20.2`,
`cargo-audit 0.22.2` (instalados para esta validación).

## Resultados automatizados

| Check | Comando | Resultado |
|---|---|---|
| Formato | `cargo fmt --all -- --check` | **PASS** |
| Lints | `cargo clippy --all-targets -- -D warnings` | **PASS** (0 warnings) |
| Suite | `cargo test --locked` | **PASS** (262 lib + 27 `gcob` + 20 `gcob-client`; 2 ignored) |
| Soak/bench | `cargo test --locked -- --include-ignored` | **PASS** (264 + 27 + 20) |
| Supply chain | `cargo deny check` | **PASS** (`advisories ok, bans ok, licenses ok, sources ok`) |
| Advisory DB | `cargo audit` | **PASS** (273 dependencias, 0 vulnerabilidades, exit 0) |

Nota: `cargo deny` reporta duplicados de versión como `warn` (política
`multiple-versions = "warn"` en `deny.toml`), no como fallo.

## Invariantes de disponibilidad

| # | Invariante | Evidencia | Resultado |
|---|---|---|---|
| 1 | `active_streams <= GLOBAL_LIMIT` | `stream_limits_concurrent_acquire_is_bounded`, `global_limit_is_shared` | PASS |
| 2 | `active_streams(client) <= CLIENT_LIMIT` | `per_client_limit_is_enforced`, `client_limit_failure_releases_global_permit` | PASS |
| 3 | `subscribers <= GLOBAL_LIMIT` | `subscribe_enforces_global_limit`, `subscriber_counter_matches_recomputed_count` | PASS |
| 4 | `subscribers(type) <= TYPE_LIMIT` | `subscribe_enforces_per_type_limit` | PASS |
| 5 | `check_rune` bajo rune inválida `<=` presupuesto pre-auth | `preauth_budget_caps_backend_attempts`, e2e `preauth_budget_cuts_before_rune_validation_over_mtls` | PASS |
| 6 | `request_body <= configured limit` | `oversized_body_is_rejected_before_any_backend_call`, e2e `oversized_body_is_rejected_over_mtls` | PASS |
| 7 | Slow subscriber no bloquea dispatch | `dispatch_does_not_block_on_full_subscriber`, `slow_subscriber_is_dropped_after_max_consecutive_drops` | PASS |
| 8 | Desconexión libera el permit de stream | `client_disconnect_unsubscribes_and_releases_permit`, `http2_max_concurrent_streams_bounds_active_streams` | PASS |
| 9 | Desconexión elimina el subscriber | `repeated_open_and_abandon_returns_to_baseline` | PASS |
| 10 | Symlink swap no redirige la lectura | `read_secure_file_symlink_race_never_reads_victim` | PASS |
| 11 | Mismo certificado ⇒ misma identidad de cuota | `spoofed_claims_share_one_certificate_budget_over_mtls` | PASS |
| 12 | Contadores globales vuelven a baseline | `stream_limits_soak_returns_to_baseline`, `availability_snapshot_returns_to_baseline` | PASS |

## Cobertura AV

| AV | Propiedad | Test | Resultado |
|---|---|---|---|
| AV-001 | Aislamiento de identidad | e2e mTLS (buckets por fingerprint) | PASS |
| AV-002 | Amplificación pre-auth | `preauth_budget_caps_backend_attempts` + e2e | PASS |
| AV-003 | Concurrencia de streams | `stream_limits_concurrent_acquire_is_bounded` + soak | PASS |
| AV-004 | Ciclo de vida de streams | lifecycle tests | PASS |
| AV-005 | Slow subscriber | router tests | PASS |
| AV-006 | Cotas de subscribers | router tests + contador | PASS |
| AV-007 | Límites HTTP/2 | `http2_max_concurrent_streams_bounds_active_streams` | PASS |
| AV-008 | Carrera symlink/TOCTOU | `read_secure_file_symlink_race_never_reads_victim` | PASS |

## Pendiente de laboratorio (no cubierto por esta validación)

1. Validación contra CLN real con HAProxy: perfiles A (legítimo), B (abusivo)
   y C (lento), según `security/availability-baseline.md`; captura de `pidstat`
   (RSS/CPU), `p99` de latencia y `baseline.json`.
2. GCOB-008: tope global de conexiones/IP delegado en HAProxy/OS por decisión;
   no se valida a nivel de proceso.
3. GCOB-015: `Arc<Event>` diferido tras el benchmark
   (`fanout_dispatch_bench`: 512 subscribers × 200 eventos ≈ 1 320 ns/entrega).

## Conclusión

No se identifican actualmente vulnerabilidades estructurales de disponibilidad
de alta severidad en la revisión estática de 0.5.4; los principales vectores
identificados (GCOB-001…GCOB-011) han sido mitigados y existen pruebas
unitarias/E2E para las propiedades de disponibilidad. La validación final de
recursos (RSS, p99, recuperación bajo ataque) requiere ejecutar el
procedimiento de laboratorio con CLN real y queda pendiente por diseño.
