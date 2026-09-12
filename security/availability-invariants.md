# Invariantes de disponibilidad y prueba adversarial acotada

Complementa `availability-baseline.md`. Define qué debe cumplirse siempre bajo
carga adversarial, cómo medirlo y qué cubre ya la suite automática frente a lo
que requiere laboratorio con CLN real.

## Invariantes

| Invariante | Límite | Evidencia |
|---|---|---|
| Streams concurrentes globales | `≤ GCOB_MAX_ACTIVE_STREAMS_GLOBAL` | `StreamLimits::active_streams` (logs/métricas) |
| Streams concurrentes por certificado | `≤ GCOB_MAX_ACTIVE_STREAMS_PER_CLIENT` | `active_streams_for(fingerprint)` |
| Subscribers del router | `≤ GCOB_MAX_SUBSCRIBERS_GLOBAL` y `≤ ..._PER_TYPE` | `EventRouter::total_subscribers` / contadores |
| Intentos de `check_rune` bajo rune inválido | `≤ GCOB_PREAUTH_LIMIT` por ventana y certificado | `AdmissionLayer`; e2e sin CLN |
| Tamaño de body aceptado | `≤ GCOB_MAX_REQUEST_BODY_BYTES` | `AuthLayer::read_body_limited` |
| Presupuesto por método ligado al certificado | 1 bucket por fingerprint, sin importar `x-client-id` | tests + e2e mTLS |
| Permisos de stream liberados al cancelar | `active_streams` vuelve a 0 tras abandono | `repeated_open_and_abandon_returns_to_baseline` |
| Estado del rate limiter acotado | nº de buckets = nº de fingerprints, no de claims | `bounded_load_with_spoofed_claims_stays_bounded` |

Tras cesar el ataque: `RSS < 2× baseline`, `p99` legítimo dentro del umbral
acordado y CLN/gcob responsivos.

## Cobertura automática (sin CLN)

`cargo test --locked` cubre:

- GCOB-001: mismo certificado + 20 claims ⇒ 1 bucket (`spoofed_client_id_...`).
- GCOB-003: presupuesto pre-auth corta antes de auth/CLN.
- GCOB-007: body oversized rechazado en streaming, antes de `check_rune`.
- GCOB-002/004: cuotas de concurrencia y ciclo de vida de streams.
- GCOB-005/006: dispatch no bloqueante, eviction de lentos y cotas.
- GCOB-001/003/007 end-to-end sobre mTLS real: `src/grpc/e2e_tests.rs`
  (servidor tonic + PKI efímera `rcgen`; `check_rune` con backend inalcanzable).
- Carga acotada: 10 000 requests / 10 certificados / 10 000 claims.

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
