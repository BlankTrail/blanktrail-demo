"""Client-side demo for BlankTrail Proxy against challenge-protected targets.

The classifier reads challenges from Cloudflare, AWS WAF, Akamai, DataDome,
PerimeterX/HUMAN and Imperva, and falls back to weaker edge attribution for
Cloudflare, Akamai, CloudFront, AWS ELB and Fastly when none of those
challenges is recognised.
"""

__version__ = "1.1.0"
