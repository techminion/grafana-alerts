# Managed alert drift detection

`grafana-alerts drift` compares the reviewed rendered artifact with live Grafana without changing
Grafana. It checks every desired rule group and every explicitly allowlisted absent group.

```bash
export GRAFANA_URL="https://grafana.example.com"
export GRAFANA_TOKEN="..."

grafana-alerts drift sites/site-a.yaml \
  --artifact-dir build/site-a \
  --output drift-report
```

The report classifies managed groups as:

- `in-sync`: the live group is a semantic match for the reviewed artifact;
- `missing`: a desired group does not exist;
- `modified`: a desired group differs, with a unified diff written beside the JSON report;
- `absent`: an allowlisted group that is not desired remains absent;
- `unexpected`: an allowlisted absent group exists in Grafana;
- `error`: Grafana could not be read for that group.

`drift-report.json` contains the authenticated identity, exact site/org/folder, reviewed manifest
fingerprint, desired/live semantic fingerprints, counts, and status. It does not contain the
Grafana token. The command exits with status 2 for drift and status 1 for read or configuration
errors. `--no-fail-on-drift` is available for exploratory local runs.

## Managed scope

The command intentionally does not enumerate or claim ownership of every group in a Grafana
folder. Its scope is the desired artifact plus exact names in `prune.allow_groups`. This prevents a
shared folder's unrelated groups from being reported as deletable or owned by this repository.

## Azure Pipelines

Set `DRIFT_ENABLED=true` to enable the read-only Drift stage. The stage publishes
`grafana-drift-report` even when drift makes the job fail. It does not run for pull requests or
during a manual deployment. Scheduled builds are explicitly prohibited from entering the Deploy
stage, even if `DEPLOY_ENABLED` is accidentally left enabled.

To run a nightly check, add an Azure YAML schedule or configure an equivalent pipeline schedule:

```yaml
schedules:
  - cron: "0 1 * * *"
    displayName: Nightly managed drift check
    branches:
      include:
        - main
    always: true
```

Configure the scheduled run with `DRIFT_ENABLED=true` and the selected site's read-capable
`GRAFANA_URL` and secret `GRAFANA_TOKEN`.
