# Authorization Boundary Definition Checklist

Boundary definition errors are the single biggest cause of RAR rejection. This isn't an exaggeration — FedRAMP assessors flag boundary issues more often than any other finding. The authorization boundary must account for every location where federal data and metadata exists, every tool and component mentioned in the SSP, and all external connections.

The most common problem: inconsistencies between boundary diagrams, data flow diagrams, and SSP narrative text. If your diagram shows 5 components but your SSP describes 7, the assessor will flag it immediately.

## Core Principles

The authorization boundary must be:
- **Complete:** Every component that processes, stores, or transmits federal data is inside the boundary
- **Accurate:** The diagram matches reality and matches the SSP narrative
- **Defensible:** You can explain why each component is included (or excluded)
- **Current:** Updated whenever the system changes

## Step 1: Inventory All Components

- [ ] **List every application component.** Web servers, application servers, API gateways, load balancers, message queues, caching layers, search engines, worker processes.
- [ ] **List every data store.** Databases (relational, NoSQL, graph), object storage (S3, Blob, GCS), file systems, data warehouses, data lakes, backup stores, log stores.
- [ ] **List every infrastructure component.** Virtual machines, containers, Kubernetes clusters, serverless functions, CDN nodes, DNS servers, NTP servers.
- [ ] **List every security tool.** Firewalls, WAFs, IDS/IPS, SIEM, vulnerability scanners, endpoint protection, DLP, secrets managers, certificate managers.
- [ ] **List every management/operations tool.** Monitoring (Datadog, New Relic, CloudWatch), CI/CD pipelines, configuration management, deployment tools, ticketing systems, code repositories.
- [ ] **List every human access point.** Admin consoles, SSH/RDP jump boxes, VPN concentrators, bastion hosts.

## Step 2: Identify External Services

This is where CSPs get tripped up most. Every third-party service that touches federal data must itself be FedRAMP authorized at the appropriate impact level.

- [ ] **Map all external service dependencies.** For each service your system uses, determine:
  - Does federal data (including metadata) flow to this service?
  - Is this service FedRAMP authorized? At what impact level?
  - Is there a direct connection or is it through an intermediary?
- [ ] **Check FedRAMP Marketplace.** Verify each external service's authorization status at marketplace.fedramp.gov.
- [ ] **Categorize each external service:**
  - **Inside boundary:** Managed by you, part of your system
  - **FedRAMP-authorized external:** Separate authorized service you integrate with (e.g., your IaaS provider)
  - **Non-FedRAMP external:** If federal data touches this service, you have a problem to solve
  - **Corporate services outside boundary:** HR systems, corporate email, etc. that don't touch federal data

Common external services that catch CSPs off guard:
- [ ] Email delivery services (SendGrid, SES, Mailgun) — does notification content contain federal data?
- [ ] Analytics services (Google Analytics, Mixpanel) — do they capture federal user behavior data?
- [ ] Error tracking (Sentry, Bugsnag) — do error payloads contain federal data?
- [ ] CDN providers — do they cache federal content?
- [ ] DNS providers — DNSSEC is a requirement but the DNS service itself may need consideration
- [ ] Code repositories — does your CI/CD pipeline have access to production federal data?
- [ ] Support/ticketing tools — do support tickets contain federal data?

## Step 3: Map Data Flows

- [ ] **Federal data ingress.** How does federal data enter your system? API, file upload, federation, manual entry?
- [ ] **Internal data flow.** How does federal data move between components? Document each hop.
- [ ] **Federal data egress.** How does federal data leave your system? API responses, exports, reports, notifications?
- [ ] **Data at rest locations.** Where is federal data stored? Primary databases, replicas, caches, logs, backups?
- [ ] **Encryption state at each point.** For each data flow and storage location, document the encryption mechanism (this feeds into the FIPS mandate).

## Step 4: Create the Required Diagrams

FedRAMP requires three distinct diagrams. They must be consistent with each other.

### Authorization Boundary Diagram
- [ ] Shows all components inside the boundary with a clear visual border
- [ ] Shows external connections crossing the boundary
- [ ] Labels every component with its name as used in the SSP
- [ ] Identifies the cloud provider infrastructure (IaaS/PaaS) layer
- [ ] Uses FedRAMP's recommended notation (or clearly defined notation)

### Network Diagram
- [ ] Shows network topology including subnets, security groups, VPCs
- [ ] Shows IP address ranges (private) and ports
- [ ] Shows firewalls, load balancers, and network segmentation
- [ ] Shows VPN/TLS tunnels for encrypted connections
- [ ] Shows internet-facing vs. internal-only components

### Data Flow Diagram
- [ ] Shows how federal data moves through the system
- [ ] Labels each flow with the data type and encryption status
- [ ] Shows authentication/authorization checkpoints
- [ ] Includes both normal operation and administrative access flows
- [ ] Shows backup and disaster recovery data flows

## Step 5: Consistency Check

This is the step most CSPs skip, and it's the step that catches them.

- [ ] **Every component in the diagrams appears in the SSP narrative.** No orphaned components.
- [ ] **Every component in the SSP narrative appears in the diagrams.** No undocumented systems.
- [ ] **Every external connection in the diagrams has a corresponding interconnection description in the SSP.**
- [ ] **The inventory workbook matches the diagrams and SSP.** Component counts, names, and types must be consistent.
- [ ] **Data flow descriptions match the data flow diagram.** If the SSP says data is encrypted with AES-256, the diagram should show encrypted flows.

## Step 6: Validate the Boundary Decision

- [ ] **Nothing is excluded that should be included.** Ask: "If this component were compromised, could federal data be affected?" If yes, it's inside the boundary.
- [ ] **Corporate services are properly separated.** Corporate email, HR systems, and other non-federal systems should be clearly outside the boundary with documented separation.
- [ ] **Development and staging environments are addressed.** If they ever contain federal data (even test data derived from production), they may need to be inside the boundary.
- [ ] **Disaster recovery infrastructure is included.** DR sites that receive replicated federal data are inside the boundary.

## Red Flags That Will Get Your RAR Rejected

- Boundary diagram doesn't match the SSP narrative
- Components listed in the SSP that don't appear in any diagram
- External services processing federal data without FedRAMP authorization
- "TBD" or placeholder entries in boundary documentation
- Boundary that's obviously too narrow (e.g., only showing the web tier when the system has multiple tiers)
- Missing data flow for administrative/management access
