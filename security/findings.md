# Informe de hallazgos — disponibilidad y recursos

Revisión estática original: commit `2e6e01e`. Estado tras Fases 0–5.

Validación automatizada 0.5.4: `security/availability-validation.md` (suite,
`cargo deny check` y `cargo audit` en verde; laboratorio con CLN real
pendiente).

## Matriz de hallazgos

| ID | Hallazgo | Severidad | Estado | Commit(s) | Regresión |
|---|---|---|---|---|---|
| GCOB-001 | `x-client-id` falsificable ⇒ bypass de cuota | Alta | **Cerrado** | `7dae27f`, `952e065` | `spoofed_client_id_claims_share_one_budget`, e2e mTLS |
| GCOB-002 | Cuota de streams por creación, sin concurrencia | Alta | **Cerrado** | `ce96a29` | `per_client_limit_is_enforced`, `global_limit_is_shared` |
| GCOB-003 | `check_rune` antes del rate limit (amplificación) | Alta | **Cerrado** | `7dae27f` | `preauth_budget_caps_backend_attempts`, e2e mTLS |
| GCOB-004 | Streams abandonados permanecen registrados | Alta | **Cerrado** | `ce96a29` | `client_disconnect_unsubscribes_and_releases_permit`, `repeated_open_and_abandon_returns_to_baseline` |
| GCOB-005 | `await` bajo `RwLock` en el router | Media/Alta | **Cerrado** | `33d4dcd` | `dispatch_does_not_block_on_full_subscriber` |
| GCOB-006 | Fan-out O(N) de eventos | Media/Alta | **Mitigado** | `33d4dcd`, `ce96a29` | `stats_track_delivered_and_dropped`, cotas de subscribers |
| GCOB-007 | Body completo antes de autorizar | Media/Alta | **Cerrado** | `7dae27f` | `oversized_body_is_rejected_before_any_backend_call`, e2e mTLS |
| GCOB-008 | Sin límite de conexiones/streams | Media/Alta | **Parcial (documentado)** | `7dae27f` | `max_concurrent_streams` + concurrencia por conexión; el cap global de conexiones queda en HAProxy/OS por decisión (ver riesgos residuales) |
| GCOB-009 | TOCTOU en operaciones de filesystem | Media | **Cerrado (servidor)** | `50f1325`, `36751ea` | `read_secure_file_rejects_symlink`, `validate_cln_source_rejects_*` |
| GCOB-010 | Dependencias sin auditoría continua | Media | **Cerrado** | `63a3bf4`, `e981976` | `cargo-deny` en CI + Dependabot |
| GCOB-011 | Orden de capas invertido (nuevo, Fase 5) | Crítica | **Cerrado** | `952e065` | `src/grpc/e2e_tests.rs` (4 tests mTLS) |
| GCOB-012 | Atomicidad de `StreamLimits` bajo alta concurrencia (validación) | Informativo | **Cerrado (T4)** | — | `stream_limits_concurrent_acquire_is_bounded`; soak `stream_limits_soak_returns_to_baseline` |
| GCOB-013 | `per_client` retiene entradas inactivas (nuevo) | Baja/Media | **Cerrado (T1–T3)** | — | `cleanup_idle_removes_inactive_clients`; `cleanup_keeps_client_with_outstanding_clone`; tarea de 300 s en `server.rs` |
| GCOB-014 | Eviction del router O(N·M) por `Vec::contains` (nuevo) | Baja | **Cerrado (T5)** | — | `dispatch_removes_dead_subscribers_without_quadratic_scan` |
| GCOB-015 | Fan-out clona `Event` por subscriber (O(N)) (nuevo) | Baja | **Cerrado (T7, diferido)** | — | Benchmark `fanout_dispatch_bench`: 512 subscribers × 200 eventos ≈ 1 320 ns/entrega; no compensa `Arc<Event>` por ahora |

### GCOB-011 — detalle

Tower invoca **primero la capa añadida primero**. La composición de la Fase 1
dejaba `RateLimitLayer` antes que `ClientIdentityLayer`, por lo que el rate
limiter veía la petición sin identidad y **rechazaba todo** con
`Client certificate required`. Detectado al construir el harness e2e de la
Fase 5; el orden correcto es:

```
identity → admission → auth → rate limit → service
```

## GCOB-010 — advisories reales encontrados y cerrados

| Advisory | Crate | Acción |
|---|---|---|
| RUSTSEC-2026-0258 | `h2 0.4.14` | Actualizado a `0.4.19` (DATA frames vacíos sin límite → memoria no acotada) |
| RUSTSEC-2026-0190 | `anyhow 1.0.102` | Actualizado a `1.0.104` (unsoundness en `downcast_mut`) |
| RUSTSEC-2026-0221 | `event-listener 5.4.1` | Actualizado a `5.4.2` (unsoundness `StackSlot`) |
| RUSTSEC-2025-0134 | `rustls-pemfile 2.2.0` | Eliminado: no se usaba y está *unmaintained* |

`cargo deny --all-features check` (0.20.2): `advisories ok, bans ok,
licenses ok, sources ok`.

## Escenario combinado del informe original

Precondición: certificado mTLS válido, rune válida o inválida.

| Paso del ataque | Antes | Ahora |
|---|---|---|
| Rotar `x-client-id` para ampliar cuota | Bucket nuevo por claim | Mismo bucket por fingerprint (GCOB-001) |
| Tormenta de runes inválidas contra CLN | 1 `check_rune` por request | Cortada por presupuesto pre-auth (GCOB-003) |
| Streams persistentes sin límite | Sin tope | Cupo global y por certificado (GCOB-002) |
| Abandonar streams sin cerrar | Subscriber/task permanente | `closed()` detecta y libera (GCOB-004) |
| Saturación por fan-out O(N) | Bloqueo del dispatcher | `try_send` + eviction + cotas (GCOB-005/006) |
| Cuerpos enormes antes de autorizar | Memoria no acotada | Tope por streaming (GCOB-007) |
| Symlink swap en lectura de claves | `fs::read` seguía el enlace | `O_NOFOLLOW` + checks por fd (GCOB-009) |

## Riesgos residuales

1. **GCOB-008**: no hay tope global de conexiones ni por IP (tonic no lo expone
   directamente). Decisión: queda en HAProxy/OS como barrera (no se implementa
   accept-loop propio en gcob). Si en el futuro se necesita defensa en
   profundidad a nivel de proceso, el diseño candidato es envolver
   `TcpIncoming` con un semáforo por conexión (`GCOB_MAX_CONNECTIONS`).
2. **GCOB-013**: el mapa `per_client` de `StreamLimits` retiene una entrada por
   fingerprint vista. Se mitiga con `cleanup_idle()` (guard
   `Arc::strong_count == 1 && available == max` bajo el lock) y una tarea
   periódica de 300 s.
3. **GCOB-006/015**: `Arc<Event>` (fan-out O(1)) no implementado; se decidirá
   con el benchmark de laboratorio. El descarte de eventos para consumidores
   lentos es intencional y está documentado.
4. **GCOB-009**: `gcob-client` (herramienta local) conserva `fs::read` para
   rutas provistas por el usuario; no es superficie de red.
5. **Validación contra CLN real**: la suite e2e usa un backend inalcanzable para
   `check_rune`; el procedimiento de laboratorio de
   `availability-invariants.md` cubre el caso con nodo real.
6. `x-client-id` solo es auditable cuando el cliente lo envía; la identidad de
   seguridad no depende de él.

## Plan de validación (AV) y trazabilidad

| AV | Propiedad | Test | Estado |
|---|---|---|---|
| AV-001 | Aislamiento de identidad (mismo cert ⇒ mismo bucket) | `spoofed_claims_share_one_certificate_budget_over_mtls`, `different_certificates_have_independent_budgets_over_mtls` | Existente |
| AV-002 | Amplificación pre-auth de `check_rune` | `preauth_budget_caps_backend_attempts`, `preauth_budget_cuts_before_rune_validation_over_mtls` | Existente |
| AV-003 | Concurrencia de streams acotada y atómica | `stream_limits_concurrent_acquire_is_bounded` (T4) + soak nightly | Cerrado |
| AV-004 | Ciclo de vida de streams (desconexión libera) | `client_disconnect_unsubscribes_and_releases_permit`, `repeated_open_and_abandon_returns_to_baseline` | Existente |
| AV-005 | Slow subscriber no bloquea el dispatch | `dispatch_does_not_block_on_full_subscriber`, `slow_subscriber_is_dropped_after_max_consecutive_drops` | Existente |
| AV-006 | Cotas de subscribers (global/tipo) | `subscribe_enforces_global_limit`, `subscribe_enforces_per_type_limit` | Existente |
| AV-007 | Límites HTTP/2 bajo carga | `http2_max_concurrent_streams_bounds_active_streams` (T8) | Cerrado |
| AV-008 | Carrera symlink/TOCTOU en lectura de certificados | `read_secure_file_symlink_race_never_reads_victim` (T9) | Cerrado |
