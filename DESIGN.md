# Design

## Source of truth
- Status: Active
- Last refreshed: 2026-06-12
- Primary product surfaces: Local React dashboard, FastAPI case/timeline/report APIs
- Evidence reviewed: Empty repository, approved v1 implementation plan, dfVFS/Sleuth Kit/Plaso official capability references, first-party dfatool MFT implementation

## Brand
- Personality: Precise, restrained, analyst-focused, evidence-first
- Trust signals: Visible hash values, parser names, confidence, provenance, reproducible report paths
- Avoid: Marketing-style hero pages, decorative graphics, unsupported AI conclusions, hidden parser assumptions

## Product goals
- Goals: Register evidence paths, preserve read-only evidence handling, extract normalized NTFS `$MFT` timeline events with dfatool, surface grounded recommendations, export reports
- Non-goals: Full forensic suite replacement, live acquisition, BitLocker decryption, browser/registry/prefetch triage in v1
- Success signals: Analyst can register an image, run analysis, inspect evidence provenance, filter events, and export CSV/JSON/Markdown

## Personas and jobs
- Primary personas: Digital forensic analyst, incident response triage analyst, student/researcher validating NTFS timelines
- User jobs: Build a file/deletion timeline, verify event provenance, identify deleted-record leads, prepare a report appendix
- Key contexts of use: Local workstation, offline evidence storage, repeatable lab validation, read-only image analysis

## Information architecture
- Primary navigation: Single operational dashboard with case list, active case work area, timeline, evidence, recommendations, reports
- Core routes/screens: Cases, evidence image registration, analysis status, timeline explorer, event evidence panel, report generation
- Content hierarchy: Active case summary first, analysis controls second, timeline/evidence review with artifact source third, recommendation/report output last

## Design principles
- Principle 1: Every investigative claim must point back to event IDs or parser provenance
- Principle 2: Controls should support repeated analyst workflow rather than presentation polish
- Tradeoffs: Dense information is preferred over large visual treatments; AI output is useful only when grounded

## Visual language
- Color: Neutral operational base with teal for verified actions, amber for caution, red only for errors
- Typography: System sans-serif, compact headings, monospaced hashes and event IDs
- Spacing/layout rhythm: 8px grid, compact panels, stable table dimensions
- Shape/radius/elevation: 6-8px radii, thin borders, no decorative shadows
- Motion: Minimal; loading spinner only for active work
- Imagery/iconography: Lucide icons for actions and evidence categories, no illustrative imagery in v1

## Components
- Existing components to reuse: None; greenfield project
- New/changed components: Case pane, evidence image form, analysis control, timeline table, evidence panel, recommendation list, report actions
- Variants and states: Loading, empty timeline, warning analysis run, selected case, selected event, disabled controls without a case/image
- Token/component ownership: CSS variables and component styles in `frontend/src/styles.css`

## Accessibility
- Target standard: WCAG AA-oriented keyboard and contrast behavior
- Keyboard/focus behavior: Native buttons/forms, visible focus rings, no pointer-only workflows
- Contrast/readability: Light neutral background, dark text, explicit warning/error contrast
- Screen-reader semantics: Main landmark, role alert for errors, table aria label for timeline
- Reduced motion and sensory considerations: Only a small spinner animation; no decorative motion

## Responsive behavior
- Supported breakpoints/devices: Desktop-first, usable tablet and mobile collapse
- Layout adaptations: Side panes stack below 1100px, forms and metrics stack below 760px
- Touch/hover differences: Buttons remain large enough for touch; hover states are supplemental

## Interaction states
- Loading: Buttons disabled and spinner shown on analysis action
- Empty: Case selection, image list, and evidence panel show explicit empty copy
- Error: API errors render in a persistent alert band
- Success: New cases, images, reports, and timeline data refresh in place
- Disabled: Analysis disabled until an image exists; report disabled until a case exists
- Offline/slow network, if applicable: Local API failures appear as actionable alert text

## Content voice
- Tone: Factual, concise, analyst-facing
- Terminology: Use artifact names (`NTFS:$MFT`, `$UsnJrnl:$J`, Recycle Bin), evidence event IDs, parser provenance
- Microcopy rules: Never state AI output as a conclusion; label it as recommendation or next step

## Implementation constraints
- Framework/styling system: FastAPI backend, React/Vite frontend, plain CSS
- Design-token constraints: No separate design system until repeated components justify it
- Performance constraints: Timeline endpoint paginates and UI requests 500 rows by default
- Compatibility constraints: v1 directly parses extracted NTFS `$MFT` files; full disk image traversal remains future work; external forensic CLIs are validation/comparison only
- Test/screenshot expectations: Backend pytest, frontend TypeScript build, browser smoke test after local dev servers start

## Open questions
- [ ] Add first-party `$UsnJrnl:$J` and Recycle Bin parsers beyond MFT output / owner: implementation / impact: stronger deletion corroboration
- [ ] Choose long-running job queue technology for multi-GB images / owner: architecture / impact: background processing reliability
