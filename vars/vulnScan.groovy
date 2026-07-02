// Dependency scan via vuln.today + Slack notification.
// Usage in a Jenkinsfile:
//   vulnScan()                                      // auto: package-lock.json + composer.lock
//   vulnScan('package-lock.json')                   // explicit file list
//   vulnScan(files: 'composer.lock', failOnVuln: true)
//   vulnScan(notifyIntervalDays: 14)
//
// A notification for a given CVE (per project) is sent at most once every
// notifyIntervalDays (default 7). State lives in JENKINS_HOME/vuln-scan-state/<project>.json
// on the controller, shared across all agents. All logic runs in Groovy on the
// controller - the agent needs no jq/curl; only the dependency file is read
// from the workspace.
//
// Requires secret text credentials in Jenkins:
//   vuln-today-api-key, vuln-today-slack-webhook

import groovy.json.JsonSlurper
import groovy.json.JsonOutput

def call(String files) {
    call(files: files)
}

def call(Map params = [:]) {
    def appName = params.appName ?: (env.JOB_NAME ?: 'unknown').tokenize('/')[0]
    def candidates = params.files ? params.files.trim().split(/\s+/) as List : ['package-lock.json', 'composer.lock']
    def present = candidates.findAll { fileExists(it) }
    if (!present) {
        echo 'Brak plikow z zaleznosciami do skanowania - pomijam.'
        return
    }

    def apiUrl = params.apiUrl ?: 'https://vuln.today/api/v1/scan'
    long intervalDays = (params.notifyIntervalDays ?: 7) as long
    def stateDir = params.stateDir ?: "${env.JENKINS_HOME ?: '/var/jenkins_home'}/vuln-scan-state"
    def statePath = "${stateDir}/${appName}.json"

    withCredentials([
        string(credentialsId: params.apiKeyCredentialId ?: 'vuln-today-api-key', variable: 'VULN_TODAY_API_KEY'),
        string(credentialsId: params.slackWebhookCredentialId ?: 'vuln-today-slack-webhook', variable: 'SLACK_WEBHOOK_URL')
    ]) {
        def responses = []
        for (f in present) {
            echo "==> Skanuje ${f} ..."
            def resp = postScan(apiUrl, env.VULN_TODAY_API_KEY, f, readFile(file: f, encoding: 'UTF-8'))
            echo summaryLine(resp)
            responses << resp
        }

        def result = buildNotification(responses, readState(statePath), appName, intervalDays)

        if (result.skipped > 0) {
            echo "==> ${result.skipped} CVE pominieto (notyfikowane w ciagu ostatnich ${intervalDays} dni)."
        }
        if (result.due > 0) {
            echo "==> Wysylam notyfikacje na Slack (${result.due} CVE) ..."
            int code = postJson(env.SLACK_WEBHOOK_URL, JsonOutput.toJson([text: result.message]))
            if (code >= 200 && code < 300) {
                writeState(statePath, result.newState)
            } else {
                echo "UWAGA: Slack webhook zwrocil HTTP ${code} - stan bez zmian"
            }
        } else if (result.total > 0) {
            echo '==> Wszystkie CVE juz notyfikowane - bez powiadomienia.'
        } else {
            echo '==> Brak podatnosci - bez notyfikacji.'
        }

        if (result.failed && params.failOnVuln) {
            error 'Skan nie przeszedl progu (threshold vuln.today)'
        }
    }
}

// multipart POST of the file to vuln.today; runs on the controller
@NonCPS
private static String postScan(String apiUrl, String apiKey, String fileName, String content) {
    def boundary = '----vulnscan' + System.nanoTime()
    def conn = (HttpURLConnection) new URL(apiUrl).openConnection()
    conn.requestMethod = 'POST'
    conn.doOutput = true
    conn.connectTimeout = 30000
    conn.readTimeout = 120000
    conn.setRequestProperty('X-API-Key', apiKey)
    conn.setRequestProperty('Content-Type', "multipart/form-data; boundary=${boundary}")
    def body = new ByteArrayOutputStream()
    body.write(("--${boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"${fileName}\"\r\nContent-Type: application/octet-stream\r\n\r\n").getBytes('UTF-8'))
    body.write(content.getBytes('UTF-8'))
    body.write(("\r\n--${boundary}--\r\n").getBytes('UTF-8'))
    conn.outputStream.withStream { it.write(body.toByteArray()) }
    int code = conn.responseCode
    String resp = (code >= 200 && code < 300 ? conn.inputStream : conn.errorStream)?.getText('UTF-8')
    if (code != 200) {
        throw new IllegalStateException("vuln.today zwrocil HTTP ${code} dla ${fileName}: ${resp}")
    }
    return resp
}

@NonCPS
private static int postJson(String urlStr, String json) {
    def conn = (HttpURLConnection) new URL(urlStr).openConnection()
    conn.requestMethod = 'POST'
    conn.doOutput = true
    conn.connectTimeout = 30000
    conn.readTimeout = 30000
    conn.setRequestProperty('Content-Type', 'application/json')
    conn.outputStream.withStream { it.write(json.getBytes('UTF-8')) }
    return conn.responseCode
}

@NonCPS
private static String summaryLine(String respJson) {
    def s = new JsonSlurper().parseText(respJson).summary
    return "    paczki: ${s.total_packages}, podatne: ${s.vulnerable_packages}, CVE: ${s.total_vulnerabilities} (critical: ${s.critical}, high: ${s.high}, medium: ${s.medium}, low: ${s.low})".toString()
}

// Filters CVEs against the notification state and builds the Slack message.
// Returns serializable types only (String/long/boolean).
@NonCPS
private static Map buildNotification(List<String> responses, String stateJson, String appName, long intervalDays) {
    def slurper = new JsonSlurper()
    def state = slurper.parseText(stateJson ?: '{}')
    def vulns = []
    boolean failed = false
    responses.each { r ->
        def data = slurper.parseText(r)
        if (data.pass != true) { failed = true }
        vulns.addAll(data.vulnerabilities ?: [])
    }

    long now = System.currentTimeMillis().intdiv(1000L)
    long cutoff = now - intervalDays * 86400L
    def due = vulns.findAll { ((state[it.cve_id] ?: 0) as long) < cutoff }

    def result = [
        total: (long) vulns.size(), due: (long) due.size(),
        skipped: (long) (vulns.size() - due.size()),
        failed: failed, message: '', newState: ''
    ]
    if (!due) { return result }

    def rows = due.groupBy { "${it['package']}@${it.current_version}" }.values().collect { g ->
        def fix = g.max { semverKey(it.fix_version) }.fix_version ?: '-'
        def cves = g.sort { -cvss(it) }.collect {
            "<${it.url ?: 'https://vuln.today/cve/' + it.cve_id}|${it.cve_id}> (${it.cvss_score ?: '-'})"
        }.join(', ')
        [pkg: g[0]['package'], ver: g[0].current_version, fix: fix, score: g.collect { cvss(it) }.max(), cves: cves]
    }.sort { -it.score }

    def lines = rows.collect { "• *${it.pkg}* ${it.ver} → *${it.fix}*: ${it.cves}" }
    def noun = due.size() == 1 ? 'podatność' : 'podatności'
    def msg = ":rotating_light: Wykryto ${due.size()} ${noun} w aplikacji *${appName}*\n\n${lines.join('\n')}"
    result.message = msg.toString()

    def newState = [:]
    newState.putAll(state)
    due.each { newState[it.cve_id] = now }
    result.newState = JsonOutput.toJson(newState)
    return result
}

@NonCPS
private static double cvss(vuln) {
    return (vuln.cvss_score ?: 0) as double
}

// version comparison key: up to 4 numeric segments
@NonCPS
private static long semverKey(String v) {
    def parts = (v ?: '0').findAll(/\d+/).collect { it as long }
    long key = 0
    for (int i = 0; i < 4; i++) {
        key = key * 100000L + (i < parts.size() ? Math.min(parts[i], 99999L) : 0L)
    }
    return key
}

// State on the controller (library code executes on the controller, not the agent)
@NonCPS
private static String readState(String path) {
    def f = new File(path)
    return f.exists() ? f.getText('UTF-8') : '{}'
}

@NonCPS
private static void writeState(String path, String json) {
    def f = new File(path)
    f.parentFile.mkdirs()
    f.setText(json, 'UTF-8')
}
