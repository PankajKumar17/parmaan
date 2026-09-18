# PRAMAAN Demo Walkthrough

This scripted walkthrough demonstrates the PRAMAAN Evidence-Carrying AI system detecting a known backdoor and a tampered inference log.

## Setup
1. A synthetic dataset is generated containing:
   - A duplicate image (perceptual hash collision)
   - A flipped label (systematic mislabeling)
   - An out-of-distribution sample (bright white image)
2. A reference logistic model is generated and its hash recorded.
3. A provenance chain of three inference records is created, signed, and hash-chained.

## Attack Injection
4. A backdoor is injected into the model by altering the weights so that images with a white pixel in the top-left corner are misclassified as the target class.
5. The second inference record in the chain is tampered with by modifying its output hash, breaking the hash chain and invalidating the Ed25519 signature.

## Execution
6. PRAMAAN runs the full assessment pipeline:
   - Cheap-tier providers (duplicates, mislabeling, OOD, annotation integrity, model identity) run first.
   - Expensive-tier providers (trigger reconstruction, fine-pruning) run because cheap-tier findings exceed the risk threshold.
   - Evidence Convergence combines cross-modality agreement into higher-confidence findings.
   - Risk Decision Matrix maps severity × confidence to dispositions (accept/review/quarantine).
   - Lineage graph is built and blast radius analysis quantifies impact.
   - Assurance Passport is generated and signed with Ed25519.
   - Staleness check confirms the passport is fresh (no manifest changes).

## Detection and Narrative
7. **Duplicate Detection**: Flags the duplicate image with high confidence (pHash Hamming distance = 0).
8. **Label Flip**: Flags the flipped label with moderate confidence (leave-one-out classifier disagrees).
9. **OOD Detection**: Flags the bright white image as an outlier in embedding space.
10. **Model Identity**: Passes (hash matches reference).
11. **Trigger Reconstruction**: Optimizes a trigger for each class; finds a small perturbation in the top-left corner that causes misclassification, producing a candidate backdoor finding with hedged language.
12. **Fine-Pruning**: Prunes low-activation neurons and observes that the suspicious behavior changes, providing supporting evidence.
13. **Evidence Convergence**: Combines the trigger reconstruction and fine-pruning findings (different modalities: behavioral and activation) into a composite finding with boosted confidence.
14. **Risk Decision**: The composite finding lands in the QUARANTINE zone (severity > 0.7, confidence > 0.7) with scope limited to the specific model.
15. **Provenance Chain Verification**: Detects the tampered record via failed Ed25519 signature and hash-chain break, reporting exactly which record failed and which property (authenticity and integrity) was violated.
16. **Assurance Passport**: Contains all findings, evidence, confidence, severity, disposition (QUARANTINE + model scope), limitations, and coverage statement. The passport is signed and includes a staleness indicator (FRESH).

## Conclusion
The system successfully demonstrates the Evidence-Carrying AI thesis: the attack is identified through multiple complementary evidence streams, converged into a trusted decision, and immortalized in a tamper-evident passport. The provenance chain detects the log tampering, ensuring the assessment itself is trustworthy.