# Baseline de disponibilidad — gcob

Procedimiento reproducible para congelar una línea base antes de aplicar los
parches de la Fase 1. Toda comparación "antes/después" se hace contra este
documento y contra un único `baseline.json` por entorno.

## Topología de laboratorio

```
loadgen (mTLS) ──▶ gcob :50003 ──mTLS──▶ HAProxy :50002 ──mTLS──▶ CLN regtest
```

No usar nodos productivos. Registrar en `baseline.json`:

- commit de gcob (`git rev-parse HEAD`)
- versión de CLN
- SHA-256 del `.env` efectivo (sin secretos en claro)
- hardware (CPU, RAM, red)

## Métricas a capturar

| Métrica | Origen | Herramienta |
|---|---|---|
| CPU gcob / RSS gcob | proceso | `pidstat -p <pid> 1` |
| CPU CLN / RSS CLN | proceso | `pidstat` |
| latencia p50/p95/p99 | loadgen | `hdrhistogram`/salida del harness |
| requests/s, errores | loadgen | resumen del harness |
| conexiones activas, streams HTTP/2 | `ss -tnp`, métricas del servidor | `ss` |
| subscribers activos | snapshot de disponibilidad (60 s) | tracing |
| `check_rune/s` | contador del bridge / logs | tracing |
| descartes de subscriber | snapshot de disponibilidad (60 s) | tracing |
| rate-limit rejects | contador de capa | tracing |
| tamaño de body aceptado | logs de rechazo | tracing |

El snapshot de disponibilidad (`server.rs`, cada 60 s) emite además
`active_streams`, `tracked_clients`, `idle_clients`, `fallback_buckets` y los
contadores `events_dispatched/delivered/dropped`, `subscribers_dropped`.

## Carga legítima inicial

Perfil del cliente A (legítimo): `Getinfo` + `Invoice` + `Xpay` dentro de cuota y
1–2 streams cortos. Duración mínima: 10 minutos o 3 ciclos completos de cuota.

## Tabla base (rellenar por entorno)

| Métrica | Valor |
|---|---|
| CPU gcob | |
| RSS gcob | |
| CPU CLN | |
| RSS CLN | |
| p99 RPC | |
| streams activos máx. | |
| subscribers máx. | |
| check_rune/s | |

## Invariantes que el parche debe mantener

- `active_streams <= GCOB_MAX_ACTIVE_STREAMS_GLOBAL`
- `active_streams(client) <= GCOB_MAX_ACTIVE_STREAMS_PER_CLIENT`
- `subscribers <= GCOB_MAX_SUBSCRIBERS_GLOBAL`
- `check_rune_total <= preauth_budget` bajo ataque de runes inválidos
- `request_body_bytes <= GCOB_MAX_REQUEST_BODY_BYTES`
- tras cesar el ataque: RSS < 2× baseline y p99 legítimo dentro del umbral
  acordado

## Formato de `baseline.json`

```json
{
  "commit": "<sha>",
  "cln_version": "<version>",
  "captured_at": "<rfc3339>",
  "host": {"cpu": "<modelo>", "ram_mb": 0, "network": "<detalle>"},
  "metrics": {
    "gcob_cpu_pct": 0,
    "gcob_rss_mb": 0,
    "cln_cpu_pct": 0,
    "cln_rss_mb": 0,
    "p50_ms": 0,
    "p95_ms": 0,
    "p99_ms": 0,
    "rps": 0,
    "max_active_streams": 0,
    "max_subscribers": 0,
    "check_rune_per_s": 0
  }
}
```
