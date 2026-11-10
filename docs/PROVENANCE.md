# Evidence provenance

An observation should identify its subject and the method used to obtain it. `evidence.schema.json` provides a small common record. Preserve exact hashes even when local paths are replaced with placeholders.

Use these evidence kinds consistently:

| Kind | What it establishes |
| --- | --- |
| `shipped_static` | Facts present in a particular shipped artifact; reachability and runtime enforcement can remain unknown. |
| `public_source` | Behavior present at a pinned public source commit; binary equivalence requires additional provenance. |
| `isolated_extracted_function` | Behavior of an exact function extracted locally from a pinned artifact, under documented mocks. |
| `synthetic_model` | Behavior of an independently implemented rule model; it does not establish product behavior. |
| `contained_runtime` | Behavior observed in a described local test environment with synthetic fixtures. |

Record a source URL at a commit rather than a moving branch. For minified application code, record the container digest, member path, member digest, and the offset convention. This project uses zero-based Unicode codepoint offsets when produced by Python text inspection; offsets are not automatically byte offsets or UTF-16 offsets.

Describe all mocks and changes to extracted inputs. Avoid publishing the full extracted application code. A local extraction tool may reference a hash and offset; its output belongs under ignored local evidence directories.

The sanitized baseline replaces the installation location with `<BUNDLE>`. It retains artifact-relative paths, version facts, hashes, and signing declarations. Its publication metadata records the hash of the original static manifest. Sanitization preserves observations while removing machine-local installation identity; it does not establish application authenticity.
