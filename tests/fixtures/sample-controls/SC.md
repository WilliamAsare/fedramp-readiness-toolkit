## SC-1

CloudWidget Enterprise has developed and documented a system and
communications protection policy. The policy covers boundary protection,
cryptographic requirements, and network segmentation. It is reviewed
annually and approved by the CISO.

## SC-7

Boundary protection is implemented through AWS VPC architecture with public
and private subnets. Web traffic enters through CloudFront CDN with AWS WAF.
API services run in private subnets with no direct internet access. Network
ACLs and security groups enforce deny-all-except-by-exception. VPC Flow Logs
capture all network traffic for audit purposes.

## SC-8

All data in transit is protected using TLS 1.2 or higher with
FIPS 140-2 validated cryptographic modules. HTTPS is enforced at
the load balancer level. Internal service-to-service communication
uses mutual TLS within the VPC.

## SC-13

FIPS 140-2 validated cryptographic modules are used for all cryptographic
operations. AWS provides FIPS endpoints for all GovCloud services. The
system uses AWS KMS with FIPS 140-2 Level 3 validated HSMs for key
management. TLS certificates use RSA-2048 or higher.

## SC-28

Data at rest is encrypted using AES-256 via AWS KMS. RDS databases use
encrypted storage volumes. S3 buckets enforce server-side encryption
(SSE-KMS). EBS volumes are encrypted by default. All encryption keys
are managed through AWS KMS with annual rotation.
