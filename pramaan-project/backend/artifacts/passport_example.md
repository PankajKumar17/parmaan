# PRAMAAN Assurance Passport

Asset ID: 0af9c67924bbba7fb8594bca41595d13e870bc355c319ad6c3139291cdeb0def

Passport version: 1\.0\.0

Issued at: 2026\-09\-18T13:12:39\.180195\+00:00



## Affected asset

\{"asset\_id": "0af9c67924bbba7fb8594bca41595d13e870bc355c319ad6c3139291cdeb0def", "hash": "0af9c67924bbba7fb8594bca41595d13e870bc355c319ad6c3139291cdeb0def", "node\_type": "dataset"\}



## Findings

### perceptual\_duplicate

Affected asset: 0001\.png

Reason: perceptual duplicate: pHash Hamming distance to 0000\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0000\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "5ef4b0b605b5fa870faeaff48b9b42aaaba8bce63a3608760af314025748a48d"\], "version": "1\.0\.0"\}

### label\_disagreement

Affected asset: 0001\.png

Reason: label disagreement: Leave\-one\-out k\-NN predicts 0, stated label=1; 5/5 neighbors agree\.; Neighbor samples: \['0003\.png', '0005\.png', '0000\.png', '0002\.png', '0006\.png'\] Severity 0\.65 and confidence 1\.0 yield review under the decision matrix\.

Confidence: 1.0

Severity: 0.65

Evidence:

- Leave\-one\-out k\-NN predicts 0, stated label=1; 5/5 neighbors agree\.

- Neighbor samples: \['0003\.png', '0005\.png', '0000\.png', '0002\.png', '0006\.png'\]

Counter-evidence:

- Neighbor vote fraction is uncalibrated; simple mean\-RGB/histogram features may confuse legitimate classes\. Corrupted neighbors, class imbalance, and feature scaling can cause confident false positives\.

Modality: ANNOTATION

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "mislabeling", "input\_hashes": \["725c4777db328932b197731b1c986c84913a069a2090deb3667b697624551c8b", "17550ce418055ff4cd54b803e704300eac4212c3edcef00f92f1e6e506a5b069", "04ae04134c8318578c932394683055fea108f3f586ff5b055613752c5f03e6f5", "8423eadd63f4494b07d11162c53a38f944f64bdd6e238483ebfc2fb47a1daf56", "68f962b48b11fe16e782b2e07047abb2dfbfdc78a67e39410e00508331a5d1e7", "e7baeb7909609738a047447dae0128d423ae95be4d0b6b00db6f542b86b2d2f2", "725c4777db328932b197731b1c986c84913a069a2090deb3667b697624551c8b", "cc143326a2646c605ea66139d7b440df7cbde18c050f1f8cf4dd30f42cfe7123", "5f95c8b4bcca621b34d1eb3ea4eab409407f7d9118993a3113eae717e287a7ae"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0002\.png

Reason: perceptual duplicate: pHash Hamming distance to 0000\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0000\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "311dbd4e0a449d5b97c088c86b9cf1080544c4c098ac7704c0b818483d45cd64"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0002\.png

Reason: perceptual duplicate: pHash Hamming distance to 0001\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0001\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["5ef4b0b605b5fa870faeaff48b9b42aaaba8bce63a3608760af314025748a48d", "311dbd4e0a449d5b97c088c86b9cf1080544c4c098ac7704c0b818483d45cd64"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0003\.png

Reason: perceptual duplicate: pHash Hamming distance to 0000\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0000\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "4439f27110c9b0fc303c1d677e5de0deafa25e1ed3aba835902f905d0ba7ef3c"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0003\.png

Reason: perceptual duplicate: pHash Hamming distance to 0001\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0001\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["5ef4b0b605b5fa870faeaff48b9b42aaaba8bce63a3608760af314025748a48d", "4439f27110c9b0fc303c1d677e5de0deafa25e1ed3aba835902f905d0ba7ef3c"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0003\.png

Reason: perceptual duplicate: pHash Hamming distance to 0002\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0002\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["311dbd4e0a449d5b97c088c86b9cf1080544c4c098ac7704c0b818483d45cd64", "4439f27110c9b0fc303c1d677e5de0deafa25e1ed3aba835902f905d0ba7ef3c"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0004\.png

Reason: perceptual duplicate: pHash Hamming distance to 0000\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0000\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "b7ae8e09f241d926608c437b5b7982dcc64ef8f7eaacb35c1c771c86e6a1b4f7"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0004\.png

Reason: perceptual duplicate: pHash Hamming distance to 0001\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0001\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["5ef4b0b605b5fa870faeaff48b9b42aaaba8bce63a3608760af314025748a48d", "b7ae8e09f241d926608c437b5b7982dcc64ef8f7eaacb35c1c771c86e6a1b4f7"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0004\.png

Reason: perceptual duplicate: pHash Hamming distance to 0002\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0002\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["311dbd4e0a449d5b97c088c86b9cf1080544c4c098ac7704c0b818483d45cd64", "b7ae8e09f241d926608c437b5b7982dcc64ef8f7eaacb35c1c771c86e6a1b4f7"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0004\.png

Reason: perceptual duplicate: pHash Hamming distance to 0003\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0003\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["4439f27110c9b0fc303c1d677e5de0deafa25e1ed3aba835902f905d0ba7ef3c", "b7ae8e09f241d926608c437b5b7982dcc64ef8f7eaacb35c1c771c86e6a1b4f7"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0005\.png

Reason: perceptual duplicate: pHash Hamming distance to 0000\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0000\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "3a5ae9d07e34bb4268bf9f932e04aa065388db83d1499363cb0e80aca107451f"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0005\.png

Reason: perceptual duplicate: pHash Hamming distance to 0001\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0001\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["5ef4b0b605b5fa870faeaff48b9b42aaaba8bce63a3608760af314025748a48d", "3a5ae9d07e34bb4268bf9f932e04aa065388db83d1499363cb0e80aca107451f"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0005\.png

Reason: perceptual duplicate: pHash Hamming distance to 0002\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0002\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["311dbd4e0a449d5b97c088c86b9cf1080544c4c098ac7704c0b818483d45cd64", "3a5ae9d07e34bb4268bf9f932e04aa065388db83d1499363cb0e80aca107451f"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0005\.png

Reason: perceptual duplicate: pHash Hamming distance to 0003\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0003\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["4439f27110c9b0fc303c1d677e5de0deafa25e1ed3aba835902f905d0ba7ef3c", "3a5ae9d07e34bb4268bf9f932e04aa065388db83d1499363cb0e80aca107451f"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0005\.png

Reason: perceptual duplicate: pHash Hamming distance to 0004\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0004\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["b7ae8e09f241d926608c437b5b7982dcc64ef8f7eaacb35c1c771c86e6a1b4f7", "3a5ae9d07e34bb4268bf9f932e04aa065388db83d1499363cb0e80aca107451f"\], "version": "1\.0\.0"\}

### composite\_duplicate

Affected asset: 0006\.png

Reason: composite duplicate: pHash Hamming distance to 0000\.png: 0/63; threshold=6; pHash Hamming distance to 0001\.png: 0/63; threshold=6; pHash Hamming distance to 0002\.png: 0/63; threshold=6; pHash Hamming distance to 0003\.png: 0/63; threshold=6; pHash Hamming distance to 0004\.png: 0/63; threshold=6; pHash Hamming distance to 0005\.png: 0/63; threshold=6; Offline mean\-RGB cosine cluster: \['0000\.png', '0006\.png'\]; single\-link similarity threshold=0\.995; Complementary signals converged for duplicate: duplicates \(PIXEL\); duplicates \(PIXEL\); duplicates \(PIXEL\); duplicates \(PIXEL\); duplicates \(PIXEL\); duplicates \(PIXEL\); duplicates \(EMBEDDING\)\.; No confidence boost: declared shared signal or reused detector\.; this convergence logic does not yet correct for detector signal correlation — treated as a known, stated limitation, not silently ignored\. Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0000\.png: 0/63; threshold=6

- pHash Hamming distance to 0001\.png: 0/63; threshold=6

- pHash Hamming distance to 0002\.png: 0/63; threshold=6

- pHash Hamming distance to 0003\.png: 0/63; threshold=6

- pHash Hamming distance to 0004\.png: 0/63; threshold=6

- pHash Hamming distance to 0005\.png: 0/63; threshold=6

- Offline mean\-RGB cosine cluster: \['0000\.png', '0006\.png'\]; single\-link similarity threshold=0\.995

- Complementary signals converged for duplicate: duplicates \(PIXEL\); duplicates \(PIXEL\); duplicates \(PIXEL\); duplicates \(PIXEL\); duplicates \(PIXEL\); duplicates \(PIXEL\); duplicates \(EMBEDDING\)\.

- No confidence boost: declared shared signal or reused detector\.

- this convergence logic does not yet correct for detector signal correlation — treated as a known, stated limitation, not silently ignored\.

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

- Average color is only an offline embedding proxy, not semantic proof\. Real locally cached CLIP/ResNet embeddings can replace embedding\_features later; unrelated images can share colors\.

- Single\-link clusters can chain; not every pair exceeds the threshold\. Both passes share image content and are not calibrated\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "69464db482ed95353c632c0128a70926bede845c6bf9aa116bbf35c5b9973000", "detector\_id": "correlation\_engine", "detector\_ids": \["duplicates"\], "input\_hashes": \["2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "311dbd4e0a449d5b97c088c86b9cf1080544c4c098ac7704c0b818483d45cd64", "3a5ae9d07e34bb4268bf9f932e04aa065388db83d1499363cb0e80aca107451f", "4439f27110c9b0fc303c1d677e5de0deafa25e1ed3aba835902f905d0ba7ef3c", "5ef4b0b605b5fa870faeaff48b9b42aaaba8bce63a3608760af314025748a48d", "b7ae8e09f241d926608c437b5b7982dcc64ef8f7eaacb35c1c771c86e6a1b4f7"\], "modalities": \["EMBEDDING", "PIXEL"\], "signal\_ids": \[\], "source\_provenance": \[\{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5"\], "version": "1\.0\.0"\}, \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["5ef4b0b605b5fa870faeaff48b9b42aaaba8bce63a3608760af314025748a48d", "2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5"\], "version": "1\.0\.0"\}, \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["311dbd4e0a449d5b97c088c86b9cf1080544c4c098ac7704c0b818483d45cd64", "2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5"\], "version": "1\.0\.0"\}, \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["4439f27110c9b0fc303c1d677e5de0deafa25e1ed3aba835902f905d0ba7ef3c", "2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5"\], "version": "1\.0\.0"\}, \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["b7ae8e09f241d926608c437b5b7982dcc64ef8f7eaacb35c1c771c86e6a1b4f7", "2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5"\], "version": "1\.0\.0"\}, \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["3a5ae9d07e34bb4268bf9f932e04aa065388db83d1499363cb0e80aca107451f", "2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5"\], "version": "1\.0\.0"\}, \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5"\], "version": "1\.0\.0"\}\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0007\.png

Reason: perceptual duplicate: pHash Hamming distance to 0000\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0000\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "1a7493ff2f2bde5f78405d46eb01abfeaea9b0a95fa5b6cec211b05faa0cf1d3"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0007\.png

Reason: perceptual duplicate: pHash Hamming distance to 0001\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0001\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["5ef4b0b605b5fa870faeaff48b9b42aaaba8bce63a3608760af314025748a48d", "1a7493ff2f2bde5f78405d46eb01abfeaea9b0a95fa5b6cec211b05faa0cf1d3"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0007\.png

Reason: perceptual duplicate: pHash Hamming distance to 0002\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0002\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["311dbd4e0a449d5b97c088c86b9cf1080544c4c098ac7704c0b818483d45cd64", "1a7493ff2f2bde5f78405d46eb01abfeaea9b0a95fa5b6cec211b05faa0cf1d3"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0007\.png

Reason: perceptual duplicate: pHash Hamming distance to 0003\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0003\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["4439f27110c9b0fc303c1d677e5de0deafa25e1ed3aba835902f905d0ba7ef3c", "1a7493ff2f2bde5f78405d46eb01abfeaea9b0a95fa5b6cec211b05faa0cf1d3"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0007\.png

Reason: perceptual duplicate: pHash Hamming distance to 0004\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0004\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["b7ae8e09f241d926608c437b5b7982dcc64ef8f7eaacb35c1c771c86e6a1b4f7", "1a7493ff2f2bde5f78405d46eb01abfeaea9b0a95fa5b6cec211b05faa0cf1d3"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0007\.png

Reason: perceptual duplicate: pHash Hamming distance to 0005\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0005\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["3a5ae9d07e34bb4268bf9f932e04aa065388db83d1499363cb0e80aca107451f", "1a7493ff2f2bde5f78405d46eb01abfeaea9b0a95fa5b6cec211b05faa0cf1d3"\], "version": "1\.0\.0"\}

### perceptual\_duplicate

Affected asset: 0007\.png

Reason: perceptual duplicate: pHash Hamming distance to 0006\.png: 0/63; threshold=6 Severity 0\.5 and confidence 0\.9 yield review under the decision matrix\.

Confidence: 0.9

Severity: 0.5

Evidence:

- pHash Hamming distance to 0006\.png: 0/63; threshold=6

Counter-evidence:

- pHash can collide on low\-detail images; legitimate repeated views are not proof of duplicate flooding\.

Modality: PIXEL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "duplicates", "input\_hashes": \["2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "1a7493ff2f2bde5f78405d46eb01abfeaea9b0a95fa5b6cec211b05faa0cf1d3"\], "version": "1\.0\.0"\}

### reference\_battery\_unverified

Affected asset: C:\\Users\\panka\\AppData\\Local\\Temp\\tmp27aw213e\\model\\model\.npz

Reason: reference battery unverified: DEGRADED: Reference battery unavailable \(InvalidProtobuf: \[ONNXRuntimeError\] : 7 : INVALID\_PROTOBUF : Load model from C:\\Users\\panka\\AppData\\Local\\Temp\\tmp27aw213e\\model\\model\.npz failed:Protobuf parsing failed\.\)\. This check was not completed\. Severity 0\.1 and confidence 0\.0 yield accept under the decision matrix\.

Confidence: 0.0

Severity: 0.1

Evidence:

- DEGRADED: Reference battery unavailable \(InvalidProtobuf: \[ONNXRuntimeError\] : 7 : INVALID\_PROTOBUF : Load model from C:\\Users\\panka\\AppData\\Local\\Temp\\tmp27aw213e\\model\\model\.npz failed:Protobuf parsing failed\.\)\. This check was not completed\.

Counter-evidence:

- An unavailable check is an assurance gap, not evidence of tampering\.

Modality: BEHAVIORAL

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "reference\_battery", "input\_hashes": \["6bb763401897191344959cdb69fd39450bb5cfa54e9e70139f2972221cc96a7d"\], "version": "1\.0\.0"\}

### weight\_stats\_unverified

Affected asset: C:\\Users\\panka\\AppData\\Local\\Temp\\tmp27aw213e\\model\\model\.npz

Reason: weight stats unverified: DEGRADED: Weight statistics unavailable \(ValueError: An ONNX reference manifest is required; no Torch execution is performed\)\. This check was not completed\. Severity 0\.1 and confidence 0\.0 yield accept under the decision matrix\.

Confidence: 0.0

Severity: 0.1

Evidence:

- DEGRADED: Weight statistics unavailable \(ValueError: An ONNX reference manifest is required; no Torch execution is performed\)\. This check was not completed\.

Counter-evidence:

- An unavailable check is an assurance gap, not evidence of tampering\.

Modality: BEHAVIORAL

Access assumptions: white\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "weight\_stats", "input\_hashes": \["6bb763401897191344959cdb69fd39450bb5cfa54e9e70139f2972221cc96a7d"\], "version": "1\.0\.0"\}

### distribution\_shift

Affected asset: 64299c9efaf23c4272ba75ec631379deff9302c64124302ea77cff8c29a4c951

Reason: distribution shift: Distribution shift: unbiased RBF MMD squared=\-0\.125, threshold=0\.1, gamma=0\.000325521; mean marginal histogram KL\(reference \|\| current\)=0\.231049\.; Embedding or image\-statistic discrepancies can be consistent with inserted or altered content, but distribution shift alone is not evidence of malicious intent\.; Energy OOD not assessed: class logits were not supplied; embeddings are not treated as logits\.; Heuristic cause attribution: illumination share=25\.0%, color share=75\.0%, blur\_noise share=0\.0%, structural share=0\.0%\.; Illumination maps to lighting/time\-of\-day; color to terrain/season; blur\_noise to sensor; structural to terrain/viewpoint\. These descriptive shares are not causal probabilities and cannot identify manipulation\. Severity 0\.8 and confidence 0\.6 yield review under the decision matrix\.

Confidence: 0.6

Severity: 0.8

Evidence:

- Distribution shift: unbiased RBF MMD squared=\-0\.125, threshold=0\.1, gamma=0\.000325521; mean marginal histogram KL\(reference \|\| current\)=0\.231049\.

- Embedding or image\-statistic discrepancies can be consistent with inserted or altered content, but distribution shift alone is not evidence of malicious intent\.

- Energy OOD not assessed: class logits were not supplied; embeddings are not treated as logits\.

- Heuristic cause attribution: illumination share=25\.0%, color share=75\.0%, blur\_noise share=0\.0%, structural share=0\.0%\.

- Illumination maps to lighting/time\-of\-day; color to terrain/season; blur\_noise to sensor; structural to terrain/viewpoint\. These descriptive shares are not causal probabilities and cannot identify manipulation\.

Counter-evidence:

- Cause\-breakdown attribution: illumination share=25\.0%, consistent with ordinary time\-of\-day/lighting variation rather than injected content; color share=75\.0% may reflect terrain/season; blur\_noise share=0\.0% may reflect sensor changes; structural share=0\.0% may reflect terrain/viewpoint\.

- Attribution is heuristic, not a causal determination\. Sampling variation, model/preprocessing changes, and legitimate operational drift can explain discrepancies; confidence is uncalibrated and review does not presume manipulation\.

Modality: EMBEDDING

Access assumptions: black\_box

Provenance: \{"config\_hash": "0f3d861c9e4a095f3c976369e2d2a306f0b109b6e197bcf82f034ce56c481031", "detector\_id": "drift\_vs\_manipulation", "input\_hashes": \["f3ec296dcdc3546bc08bddc5895a48a04dd0731dbd9d92da5d709ef9e0e1342c", "eb0c826a81440d40427ac9f39036cea0e591c3799e4a7953c5c573aa1d8cd8a4", "2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "5ef4b0b605b5fa870faeaff48b9b42aaaba8bce63a3608760af314025748a48d", "311dbd4e0a449d5b97c088c86b9cf1080544c4c098ac7704c0b818483d45cd64", "4439f27110c9b0fc303c1d677e5de0deafa25e1ed3aba835902f905d0ba7ef3c", "b7ae8e09f241d926608c437b5b7982dcc64ef8f7eaacb35c1c771c86e6a1b4f7", "3a5ae9d07e34bb4268bf9f932e04aa065388db83d1499363cb0e80aca107451f", "2e56e21861dbcc0094936bfc227eb1b67321673188257bcea489584e7eae71c5", "1a7493ff2f2bde5f78405d46eb01abfeaea9b0a95fa5b6cec211b05faa0cf1d3", "00cd5c4551d34585532b71a91cc88b7557c12ba8b2de0c8b0785a8a5e133cc3d"\], "version": "1\.0\.0"\}



## Disposition

- \{"asset\_id": "0001\.png", "finding\_index": 0, "scope": "sample", "scope\_asset\_id": "0001\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0001\.png", "finding\_index": 1, "scope": "sample", "scope\_asset\_id": "0001\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0002\.png", "finding\_index": 2, "scope": "sample", "scope\_asset\_id": "0002\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0002\.png", "finding\_index": 3, "scope": "sample", "scope\_asset\_id": "0002\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0003\.png", "finding\_index": 4, "scope": "sample", "scope\_asset\_id": "0003\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0003\.png", "finding\_index": 5, "scope": "sample", "scope\_asset\_id": "0003\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0003\.png", "finding\_index": 6, "scope": "sample", "scope\_asset\_id": "0003\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0004\.png", "finding\_index": 7, "scope": "sample", "scope\_asset\_id": "0004\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0004\.png", "finding\_index": 8, "scope": "sample", "scope\_asset\_id": "0004\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0004\.png", "finding\_index": 9, "scope": "sample", "scope\_asset\_id": "0004\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0004\.png", "finding\_index": 10, "scope": "sample", "scope\_asset\_id": "0004\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0005\.png", "finding\_index": 11, "scope": "sample", "scope\_asset\_id": "0005\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0005\.png", "finding\_index": 12, "scope": "sample", "scope\_asset\_id": "0005\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0005\.png", "finding\_index": 13, "scope": "sample", "scope\_asset\_id": "0005\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0005\.png", "finding\_index": 14, "scope": "sample", "scope\_asset\_id": "0005\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0005\.png", "finding\_index": 15, "scope": "sample", "scope\_asset\_id": "0005\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0006\.png", "finding\_index": 16, "scope": "sample", "scope\_asset\_id": "0006\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0007\.png", "finding\_index": 17, "scope": "sample", "scope\_asset\_id": "0007\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0007\.png", "finding\_index": 18, "scope": "sample", "scope\_asset\_id": "0007\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0007\.png", "finding\_index": 19, "scope": "sample", "scope\_asset\_id": "0007\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0007\.png", "finding\_index": 20, "scope": "sample", "scope\_asset\_id": "0007\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0007\.png", "finding\_index": 21, "scope": "sample", "scope\_asset\_id": "0007\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0007\.png", "finding\_index": 22, "scope": "sample", "scope\_asset\_id": "0007\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "0007\.png", "finding\_index": 23, "scope": "sample", "scope\_asset\_id": "0007\.png", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}

- \{"asset\_id": "C:\\\\Users\\\\panka\\\\AppData\\\\Local\\\\Temp\\\\tmp27aw213e\\\\model\\\\model\.npz", "finding\_index": 24, "scope": "model", "scope\_asset\_id": "C:\\\\Users\\\\panka\\\\AppData\\\\Local\\\\Temp\\\\tmp27aw213e\\\\model\\\\model\.npz", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "accept"\}

- \{"asset\_id": "C:\\\\Users\\\\panka\\\\AppData\\\\Local\\\\Temp\\\\tmp27aw213e\\\\model\\\\model\.npz", "finding\_index": 25, "scope": "model", "scope\_asset\_id": "C:\\\\Users\\\\panka\\\\AppData\\\\Local\\\\Temp\\\\tmp27aw213e\\\\model\\\\model\.npz", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "accept"\}

- \{"asset\_id": "64299c9efaf23c4272ba75ec631379deff9302c64124302ea77cff8c29a4c951", "finding\_index": 26, "scope": "batch", "scope\_asset\_id": "64299c9efaf23c4272ba75ec631379deff9302c64124302ea77cff8c29a4c951", "scope\_note": "No scoped lineage ancestor; using declared scope or sample fallback\.", "verdict": "review"\}



## Limitations

- this convergence logic does not yet correct for detector signal correlation — treated as a known, stated limitation, not silently ignored\.

- Naive\-correlation limitation: same\-modality agreement receives no confidence boost; declared shared signals or reused detectors also suppress the boost\. Cross\-modality boosts are heuristic, not calibrated probabilities\.

- Canonical serialization uses six\-decimal numeric precision; finer differences are not authenticated\.



## Coverage statement

- version: 1\.0\.0

- generated\_at: 2026\-09\-18T13:12:39\.179544\+00:00

- supported\_attack\_classes: \{"OOD insertion": "cf\. MITRE ATLAS: Evade ML Model", "candidate backdoors": "cf\. MITRE ATLAS: Backdoor ML Model", "inference tampering &amp; replay": "cf\. MITRE ATLAS: AI Model Inference API Access \(related access surface; replay is not a direct taxonomy equivalence\)", "label\-flip": "cf\. MITRE ATLAS: Poison Training Data", "model substitution": "cf\. MITRE ATLAS: ML Supply Chain Compromise", "near\-duplicate flooding": "cf\. MITRE ATLAS: Poison Training Data"\}

- access\_assumptions: \{"capabilities": \{"Fine\-Pruning": \{"black\_box": "no", "gray\_box": "no", "white\_box": "yes"\}, "Merkle activation commitment": \{"black\_box": "no", "gray\_box": "partial", "white\_box": "yes"\}, "Model Identity \(hash check\)": \{"black\_box": "yes", "gray\_box": "yes", "white\_box": "yes"\}, "Reference\-battery comparison": \{"black\_box": "yes \(output\-only\)", "gray\_box": "yes", "white\_box": "yes"\}, "Trigger reconstruction": \{"black\_box": "no", "gray\_box": "partial", "white\_box": "yes"\}, "Weight/activation statistics": \{"black\_box": "no", "gray\_box": "partial", "white\_box": "yes"\}\}, "used": \["black\_box", "white\_box"\]\}

- black\_box\_fallback: Use output\-only reference\-battery comparisons when outputs and a trusted reference are available\. Hash identity requires a supplied model file and trusted digest even in black\-box mode\. Skip unavailable weights, activations, gradient\-based reconstruction, fine\-pruning, and Merkle activation commitments; disclose skipped/degraded checks as assurance debt\. Fallback execution is not asserted without assessment evidence\.

- limitations: \["this convergence logic does not yet correct for detector signal correlation — treated as a known, stated limitation, not silently ignored\.", "Naive\-correlation limitation: same\-modality agreement receives no confidence boost; declared shared signals or reused detectors also suppress the boost\. Cross\-modality boosts are heuristic, not calibrated probabilities\.", "Supported attack classes describe available checks, not guaranteed detection or proof of absence\.", "Candidate backdoors remain hypotheses; unknown attacks and unobserved triggers are unsupported\.", "Inference computation checks provide sampled, partial assurance, not a full cryptographic guarantee \(zkML out of scope\)\.", "Replay detection requires persistent verifier state; a passport signature alone does not establish freshness\.", \{"evaluation": "ablation", "note": "No robustness guarantee is inferred; missing, negative, and unoptimized results remain visible\.", "results": null, "status": "not evaluated"\}, \{"evaluation": "adaptive\_attacker", "note": "No robustness guarantee is inferred; missing, negative, and unoptimized results remain visible\.", "results": null, "status": "not evaluated"\}\]

- assurance\_debt: \[\]

- ablation\_results: null

- adaptive\_attacker\_results: null



## Signature

Algorithm: Ed25519

Signature: dfe361dca1b2ea29278283fb0f6e7e8e077c9dc15e291978f3267c20eebc7ed29764e17e3e0e2b4759325b030645561d84d16f4aa2fb8831d4e3bbd5b4ecd906

Public key fingerprint (SHA-256): 9a256a1fec2fb1acf1ee6a344312e6f541b0381a97470a3fbe0e8e08579d16f5
