# Security policy

keeper is pre-alpha, maintained by one person, and has **not** been audited by a third party.
It is the root of trust for every object in a sealbox that uses it; treat every claim in the README as unverified until it is.

Report vulnerabilities through GitHub's private vulnerability reporting on this repository ("Security" tab),
not in a public issue. Reports are answered on a best-effort basis, usually within a week, and confirmed issues
are fixed before they are discussed publicly.

In scope: anything that recovers a master key or a wrapped key without a valid token for that key name,
bypasses the rate limit, or removes a call from the audit log.
Out of scope: a compromised keeper host or a stolen master key.
