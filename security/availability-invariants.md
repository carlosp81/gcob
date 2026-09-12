# Invariantes de disponibilidad y prueba adversarial acotada

Complementa `availability-baseline.md`. Define qué debe cumplirse siempre bajo
carga adversarial, cómo medirlo y qué cubre ya la suite automática frente a lo
que requiere laboratorio con CLN real.

## Invariantes

| # | Invariante | Límite | Evidencia | Test |
|---|---|---|---|---|
| 1 | Streams concurrentes globales | `≤ GCOB_MAX_ACTIVE_STREAMS_GLOBAL` | `StreamLimits::active_streams` | `stream_limits_concurrent_acquire_is_bounded`, `global_limit_is_shared` |
| 2 | Streams concurrentes por certificado | `≤ GCOB_MAX_ACTIVE_STREAMS_PER_CLIENT` | `active_streams_for(fingerprint)` | `per_client_limit_is_enforced`, `client_limit_failure_releases_global_permit` |
| 3 | Subscribers globales | `≤ GCOB_MAX_SUBSCRIBERS_GLOBAL` | contador O(1) + `total_subscribers` | `subscribe_enforces_global_limit`, `subscriber_counter_matches_recomputed_count` |
| 4 | Subscribers por tipo | `≤ GCOB_MAX_SUBSCRIBERS_PER_TYPE` | contador por tipo | `subscribe_enforces_per_type_limit` |
| 5 | Intentos de `check_rune` con rune inválida | `≤ GCOB_PREAUTH_LIMIT` por ventana y certificado | `AdmissionLayer` | `preauth_budget_caps_backend_attempts` |
| 6 | Tamaño de body aceptado | `≤ GCOB_MAX_REQUEST_BODY_BYTES` | `AuthLayer::read_body_limited` | `oversized_body_is_rejected_before_any_backend_call` |
| 7 | Slow subscriber no bloquea dispatch | dispatch sin `await` de envío | `try_send` + eviction | `dispatch_does_not_block_on_full_subscriber` |
| 8 | Desconexión libera el permit de stream | `active_streams` vuelve a 0 | RAII `StreamPermit` | `client_disconnect_unsubscribes_and_releases_permit` |
| 9 | Desconexión elimina el subscriber | `total_subscribers` vuelve a 0 | `next_event_or_cancel` | `repeated_open_and_abandon_returns_to_baseline` |
| 10 | Symlink swap no redirige la lectura | contenido siempre del fd abierto | `O_NOFOLLOW` + `fstat/fgetxattr` | `read_secure_file_symlink_race_never_reads_victim` |
| 11 | Mismo certificado ⇒ misma identidad de cuota | 1 bucket por fingerprint | `ClientIdentityLayer` | `spoofed_claims_share_one_certificate_budget_over_mtls` |
| 12 | Contadores globales vuelven a baseline | `active_streams == 0` y `subscribers == 0` tras la carga | RAII + unsubscribe | soak nightly `stream_limits_soak_returns_to_baseline` |

Tras cesar el ataque: `RSS < 2× baseline`, `p99` legítimo dentro del umbral
acordado y CLN/gcob responsivos. Los tests de soak están marcados `#[ignore]` y
se ejecutan en el workflow nightly (`--include-ignored`).

## Cobertura automática (sin CLN)

`cargo test --locked` cubre:

- GCOB-001: mismo certificado + 20 claims ⇒ 1 bucket (`spoofed_client_id_...`).
- GCOB-003: presupuesto pre-auth corta antes de auth/CLN.
- GCOB-007: body oversized rechazado en streaming, antes de `check_rune`.
- GCOB-002/004: cuotas de concurrencia y ciclo de vida de streams.
- GCOB-005/006: dispatch no bloqueante, eviction de lentos y cotas.
- GCOB-001/003/007 end-to-end sobre mTLS real: `src/grpc/e2e_tests.rs`
  (servidor tonic + PKI efímera `rcgen`; `check_rune` con backend inalcanzable).
- GCOB-012/013: atomicidad de `StreamLimits` bajo concurrencia (100 tareas),
  cleanup de clientes idle con guard anti-carrera y soak nightly.
- AV-007: `max_concurrent_streams = 1` con 8 streams concurrentes (MockCln
  válido + contador de handlers activos); el máximo observado es 1 y el
  contador vuelve a 0 al cancelar.
- AV-008: carrera real de symlink contra `read_secure_file` en `/tmp`.
- Carga acotada: 10 000 requests / 10 certificados / 10 000 claims.

Los tests marcados `#[ignore]` (soak de `StreamLimits` y benchmark de fan-out)
se ejecutan en `.github/workflows/nightly.yml` (`cargo test --locked --
--include-ignored`). El snapshot de disponibilidad de `server.rs` (60 s) publica
los gauges que se comparan contra los invariantes 1–4, 7 y 12.

## Cobertura de laboratorio (con CLN real)

Solo el nodo de laboratorio valida `check_rune` contra CLN. Procedimiento:

1. Congelar `baseline.json` (ver `availability-baseline.md`).
2. Perfil A — legítimo: `getinfo`/`invoice` dentro de cuota + 1–2 streams.
3. Perfil B — abusivo: `x-client-id` rotado, runes inválidas, creación y
   abandono de streams, reconexiones.
4. Perfil C — lento: stream que no consume; verificar eviction tras
   `GCOB_SLOW_SUBSCRIBER_MAX_DROPS` sin degradar al resto.
5. Durante la prueba, muestrear cada 5 s:

```bash
pidstat -p "$(pgrep -f 'gcob serve')" 1 > gcob.pidstat &
pidstat -p "$(pgrep -f lightnigd)" 1 > cln.pidstat &
ss -tn state established '( sport = :50003 )' | wc -l
```

6. Comparar contra baseline e invariantes; adjuntar `pidstat`, salida del
   harness y `baseline.json` al informe.

## Criterio de aceptación

- 0 bypass de cuota entre identidades lógicas del mismo certificado.
- 0 llamadas a CLN por runes inválidas más allá del presupuesto pre-auth.
- `active_streams` y `subscribers` en línea base tras 100 ciclos abrir/cerrar.
- Sin crecimiento monótono de RSS durante el ataque.
- El throughput legítimo se recupera al detener la carga.
