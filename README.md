# Grafana Alerts

Git is the source of truth for Grafana-managed alert rules across multiple Grafana
organizations/sites. Shared Jinja templates contain the alert structure; each site YAML contains
only its data source, folder, labels, thresholds, queries, and other permitted overrides. Azure
DevOps validates and renders every change, then deploys only after a commit reaches `main` and the
deployment gate is enabled.

## Repository layout

```text
.
├── templates/                 # Shared rule-group templates
├── sites/                     # Non-secret organization/site configuration
├── src/grafana_alerts/        # Renderer, validator, Grafana client, and CLI
├── tests/
├── azure-pipelines.yml
└── pyproject.toml
```

`build/` is generated and ignored. Never commit Grafana tokens, passwords, webhook URLs, or other
secrets. Store them as secret Azure DevOps variables.

## Why Jinja uses `[[ ... ]]`

Grafana annotations use Go-template expressions such as `{{ $labels.instance }}`. This project uses
`[[ variable ]]` for Jinja so the two template languages do not collide:

```yaml
description: "CPU is above [[ group.cpu_threshold_percent ]]% on {{ $labels.instance }}"
```

## Site configuration

Copy the example and change the organization-specific values:

```bash
cp sites/example.yaml sites/site-a.yaml
```

Each configured group names a template and supplies its inputs. The minimum Grafana section is:

```yaml
grafana:
  org_id: 1
  folder_uid: infrastructure-alerts
  datasource_uid: prometheus-main
```

The folder and data source must already exist. A service-account token must belong to the target
Grafana organization and have permission to read the identity endpoint and provision alert rules.
The CLI always verifies the token with `/api/user`; it does not trust a username supplied through a
file or environment variable.

### SBCP import

`sites/sbcp.yaml` represents the supplied SBCP provisioning export:

- organization ID: `10`
- folder: `SBCP`
- 28 rule groups
- 676 alert rules
- evaluation interval: 60 seconds
- Prometheus UID: `afq2sc9yp1u68f`
- Loki UID: `ffq2s7k65isxse`

The export contains the folder name but not its UID. The SBCP folder UID is configured as
`cfq41jl2svbi8a` in `sites/sbcp.yaml`.

The generated templates live under `templates/imported/sbcp/`. They preserve the rule UIDs,
queries, thresholds, pending durations, labels, annotations, error/no-data behavior, and paused
state. Only the site, environment, organization ID, folder UID, and data source UIDs are
parameterized.

To regenerate them from a newer Grafana export:

```bash
python scripts/import_grafana_export.py sbcp-alerts.json \
  --site-name SBCP \
  --environment PROD \
  --folder-uid cfq41jl2svbi8a \
  --datasource prometheus=afq2sc9yp1u68f \
  --datasource loki=ffq2s7k65isxse \
  --output templates/imported/sbcp \
  --site-config sites/sbcp.yaml
```

### Per-site rule overrides

Templates retain the imported SBCP values as defaults. Override only the rules that differ in a
site configuration:

```yaml
groups:
  - name: Fluent-Bit-Alerts
    template: imported/sbcp/fluent-bit-alerts.json.j2
    thresholds:
      afd3j2l6om1a8d: [1]
    for_overrides:
      afd3j2l6om1a8d: 10m
    query_overrides:
      afd3j2l6om1a8d:
        A: up{site_name="ANOTHER_SITE"}
    rule_overrides:
      afd3j2l6om1a8d:
        labels:
          og_priority: P1
```

`rule_overrides` is a recursive mapping merge; lists are replaced as a whole.

## Local usage

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

grafana-alerts validate sites/example.yaml
grafana-alerts render sites/example.yaml
```

For read-only comparison or deployment:

```bash
export GRAFANA_URL="https://grafana.example.com"
export GRAFANA_TOKEN="..."

grafana-alerts whoami
grafana-alerts plan sites/site-a.yaml
grafana-alerts deploy sites/site-a.yaml
```

`plan` performs only authenticated reads. `deploy` uses Grafana's create/update rule-group endpoint,
which replaces the target group with the rendered group. This first version intentionally does not
delete groups that have disappeared from Git.

## Azure DevOps

Create the pipeline from `azure-pipelines.yml`, then define:

| Variable | Secret | Purpose |
|---|---:|---|
| `GRAFANA_URL` | No | Base URL of the selected Grafana site |
| `GRAFANA_TOKEN` | Yes | Org-scoped service-account token |
| `DEPLOY_ENABLED` | No | Must equal `true` before the main-branch deploy step runs |

Choose the site YAML with the pipeline's `site` parameter. PR runs lint, test, validation, and
rendering but never deploy. A main-branch run deploys only when `DEPLOY_ENABLED=true`.

For several organizations, use one environment/stage or variable group per organization so each
token remains scoped to exactly one Grafana org. Do not use a single unrestricted admin token for
all sites.

## Commands

| Command | Behavior |
|---|---|
| `validate` | Strictly renders and validates every configured group |
| `render` | Writes deterministic JSON payloads under `build/<site>/` |
| `whoami` | Shows the identity returned by Grafana for the token |
| `plan` | Reports whether each desired group would be created or updated |
| `deploy` | Creates or replaces desired rule groups; performs no deletions |

## API compatibility

The client currently uses Grafana's `/api/v1/provisioning` rule-group endpoint. Grafana 13 marks
legacy `/api` endpoints as deprecated but states that they remain operational while `/apis`
coverage is still being completed. Endpoint construction is isolated in `GrafanaClient` so a future
App Platform adapter will not change templates or site files.

## Next milestones

1. Replace the example expressions with exported, production-tested alert groups.
2. Add interactive data source, metric, label, and PromQL query discovery using the authenticated
   Grafana identity and its existing permissions.
3. Add a true semantic diff to `plan` and require an approval before production deployment.
4. Add opt-in pruning with an explicit allowlist; keep deletion disabled by default.
