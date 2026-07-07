# OCSF DataFormat Example

This example demonstrates Apache Camel's OCSF (Open Cybersecurity Schema Framework) DataFormat. OCSF is an open standard for security event logging, used by AWS Security Hub, Splunk, CrowdStrike, and other security tools.

The example exposes REST endpoints that receive OCSF events as JSON, unmarshal them to typed Java objects, extract relevant fields, and return a response. There's also an optional integration with Ollama for summarizing security findings.

## Prerequisites

The `camel-ocsf` module requires Camel 4.18.0 or later.

If you're working with a SNAPSHOT build:

```shell
cd /path/to/camel
mvn clean install -pl components/camel-ocsf -am -DskipTests
mvn clean install -pl dsl/camel-jbang -am -DskipTests
```

## Running the Example

```shell
jbang -Dcamel.jbang.version=4.18.0-SNAPSHOT camel@apache/camel run --port 8081 --properties=application.properties --dep camel:ocsf --dep camel:langchain4j-chat --dep=mvn:dev.langchain4j:langchain4j-ollama:1.10.0 ocsf.camel.yaml
```

The server starts on port 8081. Check the health endpoint to verify:

```shell
curl http://localhost:8081/health
```

## Available Endpoints

|Endpoint |Description|
|---|---|
|`POST /api/ocsf/detection-finding` |Security detection findings (alerts from SIEM, EDR, etc.)|
|`POST /api/ocsf/detection-finding/summarize` |Same as above, but sends the finding to Ollama for analysis (requires Ollama running)|
|`POST /api/ocsf/authentication` |Login/logout events|
|`POST /api/ocsf/vulnerability-finding` |CVE and vulnerability scan results|
|`POST /api/ocsf/network-activity` |Network traffic and connection events|
|`POST /api/ocsf/file-activity` |File system operations (create, modify, delete)|
|`POST /api/ocsf/process-activity` |Process execution events (launch, terminate)|
|`POST /api/ocsf/event` |Generic OCSF events|
|`GET /health` |Health check|

## Testing the Endpoints

The `test/` directory contains sample OCSF events. Here's how to test each endpoint:

### Detection Findings

Detection findings represent security alerts from tools like AWS GuardDuty, CrowdStrike, or your SIEM.

```shell
curl -X POST http://localhost:8081/api/ocsf/detection-finding \
  -H "Content-Type: application/json" \
  -d @test/detection-finding.json
```

The route extracts finding info, severity, cloud context, and remediation steps, then logs a formatted summary.

Sample files:

* `detection-finding.json` - Suspicious Secrets Manager API call from external IP
* `detection-finding_1.json` - Crypto mining instances launched from China
* `detection-finding_2.json` - Brute-force attack on authentication API
* `detection-finding_3.json` - IAM privilege escalation attempt
* `detection-finding_4.json` - SQL injection with data exfiltration
* `detection-finding_5.json` - Lambda supply chain attack
* `detection-finding_6.json` - Container IMDS credential theft

### Authentication Events

Authentication events track login attempts, MFA usage, and session activity.

```shell
curl -X POST http://localhost:8081/api/ocsf/authentication \
  -H "Content-Type: application/json" \
  -d @test/authentication_1.json
```

The route extracts user info, source IP, destination service, MFA status, and authentication protocol.

Sample files:

* `authentication_1.json` - Successful login with MFA from corporate IP
* `authentication_2.json` - Failed login from Tor exit node

### Vulnerability Findings

Vulnerability findings come from scanners like Amazon Inspector, Qualys, or Trivy.

```shell
curl -X POST http://localhost:8081/api/ocsf/vulnerability-finding \
  -H "Content-Type: application/json" \
  -d @test/vulnerability-finding_1.json
```

The route extracts CVE ID, CVSS score, affected package, and whether a fix is available.

Sample files:

* `vulnerability-finding_1.json` - Log4Shell (CVE-2021-44228) in production
* `vulnerability-finding_2.json` - OpenSSL buffer overflow (CVE-2022-3602)

### Network Activity

Network activity events capture traffic flows, blocked connections, and protocol details.

```shell
curl -X POST http://localhost:8081/api/ocsf/network-activity \
  -H "Content-Type: application/json" \
  -d @test/network-activity_1.json
```

The route extracts source/destination IPs and ports, traffic volume, TLS info, and action taken.

Sample files:

* `network-activity_1.json` - SSH brute force attack blocked
* `network-activity_2.json` - Outbound C2 beaconing detected

### File Activity

File activity events track file system operations from EDR tools.

```shell
curl -X POST http://localhost:8081/api/ocsf/file-activity \
  -H "Content-Type: application/json" \
  -d @test/file-activity_1.json
```

The route extracts file name, path, size, hashes, the process that performed the action, and user context.

Sample files:

* `file-activity_1.json` - Mimikatz dropped via encoded PowerShell command

### Process Activity

Process activity events track process execution, useful for detecting malicious behavior.

```shell
curl -X POST http://localhost:8081/api/ocsf/process-activity \
  -H "Content-Type: application/json" \
  -d @test/process-activity_1.json
```

The route extracts process name, PID, command line, parent process chain, and actor information.

Sample files:

* `process-activity_1.json` - Recon commands spawned from malicious Excel macro

## Testing All Events

Run all test files:

```shell
# Detection findings
for f in test/detection-finding*.json; do
  echo "Testing $f"
  curl -s -X POST http://localhost:8081/api/ocsf/detection-finding \
    -H "Content-Type: application/json" -d @$f | jq -r '.status'
done

# Authentication
for f in test/authentication*.json; do
  echo "Testing $f"
  curl -s -X POST http://localhost:8081/api/ocsf/authentication \
    -H "Content-Type: application/json" -d @$f | jq -r '.status'
done

# Vulnerability findings
for f in test/vulnerability-finding*.json; do
  echo "Testing $f"
  curl -s -X POST http://localhost:8081/api/ocsf/vulnerability-finding \
    -H "Content-Type: application/json" -d @$f | jq -r '.status'
done

# Network activity
for f in test/network-activity*.json; do
  echo "Testing $f"
  curl -s -X POST http://localhost:8081/api/ocsf/network-activity \
    -H "Content-Type: application/json" -d @$f | jq -r '.status'
done

# File activity
curl -s -X POST http://localhost:8081/api/ocsf/file-activity \
  -H "Content-Type: application/json" -d @test/file-activity_1.json | jq -r '.status'

# Process activity
curl -s -X POST http://localhost:8081/api/ocsf/process-activity \
  -H "Content-Type: application/json" -d @test/process-activity_1.json | jq -r '.status'
```

## Using the OCSF DataFormat

The OCSF DataFormat unmarshals JSON to typed POJOs:

```yaml
- unmarshal:
    ocsf:
      unmarshalType: org.apache.camel.dataformat.ocsf.model.DetectionFinding
```

After unmarshalling, you can access fields directly:

```yaml
- setHeader:
    name: severity
    simple: "${body.additionalProperties[severity]}"
- setHeader:
    name: findingTitle
    simple: "${body.findingInfo.title}"
```

Some fields are direct properties on the Java class (like `findingInfo`, `vulnerabilities`), while others are in `additionalProperties` (like `severity`, `time_dt`). Check the generated model classes in `camel-ocsf` if you need to know which is which.

To marshal back to JSON:

```yaml
- marshal:
    ocsf: {}
```

## Ollama Integration

The `/api/ocsf/detection-finding/summarize` endpoint sends findings to Ollama for analysis.

Start Ollama using Camel's infra command:

```shell
camel infra run ollama 
```

Configuration in `application.properties`:

```properties
ollama.base.url=http://localhost:11434
ollama.model.name=granite4:3b
```

Test the summarization:

```shell
curl -X POST http://localhost:8081/api/ocsf/detection-finding/summarize \
  -H "Content-Type: application/json" \
  -d @test/detection-finding.json | jq .
```

## Supported OCSF Event Classes

The DataFormat includes POJOs for most OCSF event classes:

* **Findings**: DetectionFinding, VulnerabilityFinding, ComplianceFinding
* **IAM**: Authentication, AuthorizeSession, AccountChange, GroupManagement
* **System Activity**: FileActivity, ProcessActivity, MemoryActivity, ModuleActivity
* **Network Activity**: NetworkActivity, HttpActivity, DnsActivity, SshActivity
* **Discovery**: DeviceInventoryInfo, UserInventoryInfo

## Links

* [OCSF Schema Browser](https://schema.ocsf.io/)
* [OCSF GitHub](https://github.com/ocsf/ocsf-schema)
* [AWS Security Hub OCSF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html)
* [Ollama](https://ollama.ai)

## Help

If you have questions or run into problems, reach out on the [Camel mailing list](https://camel.apache.org/community/support/) or [Zulip chat](https://camel.zulipchat.com/).
