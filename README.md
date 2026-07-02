# vuln-today-jenkins-lib

Jenkins Shared Library that scans project dependencies with the [vuln.today](https://vuln.today) API and posts notifications about discovered CVEs to Slack.

## Features

- Scans lockfiles: `package-lock.json` (npm) and `composer.lock` (PHP), auto-detecting which are present
- Slack notification (webhook): vulnerable packages sorted by CVSS, fixed version, clickable CVE links
- Deduplication: a notification for a given CVE per project is sent at most once every N days (default 7)
- Zero agent dependencies: all logic (HTTP, JSON parsing, state) runs on the controller in pure Groovy, no jq/curl
- Dedup state kept in `JENKINS_HOME/vuln-scan-state/<project>.json`, shared across all agents
- Optional build failure when the scan exceeds the threshold (`failOnVuln`)

## Requirements

- Jenkins with multibranch pipelines (the scan is meant to run on pull request builds)
- The library registered as a **Global Trusted Pipeline Library** (the code uses `new File`/`URL`, which the untrusted-library sandbox would reject)
- Secret text credentials:
  - `vuln-today-api-key` - vuln.today API key
  - `vuln-today-slack-webhook` - Slack webhook URL

## Installation

Manage Jenkins → System → Global Trusted Pipeline Libraries:

- Name: `vuln-today`
- Default version: `main`
- Retrieval method: Modern SCM → Git → URL of this repository

## Usage

```groovy
@Library('vuln-today') _

pipeline {
  ...
  stages {
    stage('Dependency Scan') {
      when { changeRequest() }
      steps {
        vulnScan()
      }
    }
  }
}
```

Call variants:

```groovy
vulnScan()                                        // auto: package-lock.json + composer.lock
vulnScan('package-lock.json')                     // explicit file list
vulnScan(files: 'composer.lock', failOnVuln: true) // fail the build when the scan exceeds the threshold
vulnScan(notifyIntervalDays: 14)                  // less frequent notification repeats
```

Parameters:

| Parameter | Default | Description |
|---|---|---|
| `files` | auto-detection | Space-separated list of files to scan |
| `failOnVuln` | `false` | Fail the build when the scan exceeds the vuln.today threshold |
| `notifyIntervalDays` | `7` | How often to repeat a notification for the same CVE (days) |
| `appName` | first segment of `JOB_NAME` | Project name used in the notification and the state file |
| `stateDir` | `JENKINS_HOME/vuln-scan-state` | Directory of the dedup state file |
| `apiKeyCredentialId` | `vuln-today-api-key` | Credential ID holding the API key |
| `slackWebhookCredentialId` | `vuln-today-slack-webhook` | Credential ID holding the webhook URL |

## Notification format

```
:rotating_light: Wykryto 18 podatności w aplikacji XYZ

• axios 1.7.2 → 1.16.0: CVE-2026-42043 (10.0), CVE-2026-42264 (9.1), ...
• rollup 4.18.0 → 4.59.0: CVE-2026-27606 (8.8), CVE-2024-47068 (-)
```

CVE names link to their details on vuln.today; `(-)` marks a CVE without a computed CVSS score. Notification texts are currently in Polish.
