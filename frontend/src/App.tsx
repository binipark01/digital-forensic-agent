import {
  AlertTriangle,
  Archive,
  Bot,
  CheckCircle2,
  ClipboardList,
  Database,
  FileClock,
  FileDown,
  FileSearch,
  Filter,
  FolderInput,
  HardDrive,
  ListRestart,
  Loader2,
  PackageCheck,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck,
  XCircle
} from "lucide-react";
import type { FormEvent, ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000";

type CaseRecord = {
  id: string;
  name: string;
  examiner: string;
  description: string;
  created_at: string;
  image_count: number;
  event_count: number;
};

type ImageRecord = {
  id: string;
  path: string;
  format: string;
  size_bytes: number;
  sha256: string;
  registered_at: string;
};

type AnalysisRun = {
  id: string;
  status: string;
  parser_mode: string;
  warning: string;
  warnings?: readonly AnalysisWarning[];
  event_count: number;
  tool_versions: Record<string, unknown>;
};

type AnalysisWarning = {
  readonly code: string;
  readonly artifact_id?: string;
  readonly artifact_type?: string;
  readonly message: string;
};

type TimelineEvent = {
  id: string;
  timestamp: string | null;
  source_artifact: string;
  record_id: string;
  path: string;
  action: string;
  confidence: number;
  provenance: Record<string, unknown>;
  attributes: Record<string, unknown>;
};

type Recommendation = {
  title: string;
  rationale: string;
  evidence_event_ids: string[];
  next_steps: string[];
};

type Report = {
  id: string;
  format: string;
  path: string;
  generated_at: string;
  event_count: number;
};

type EvidenceSource = {
  readonly id?: string;
  readonly source_id?: string;
  readonly case_id?: string;
  readonly name?: string;
  readonly path?: string;
  readonly root_path?: string;
  readonly source_type?: string;
  readonly registered_at?: string;
  readonly metadata?: Record<string, unknown>;
};

type CollectionTarget = {
  readonly id?: string;
  readonly target_id?: string;
  readonly artifact_type?: string;
  readonly type?: string;
  readonly label?: string;
  readonly path?: string;
  readonly relative_path?: string;
  readonly resolved_path?: string | null;
  readonly status?: string;
  readonly classification?: string;
  readonly found?: boolean;
  readonly reason?: string;
  readonly parser_hint?: string | Record<string, unknown>;
  readonly size_bytes?: number;
  readonly sha256?: string;
};

type CollectionPlan = {
  readonly id?: string;
  readonly plan_id?: string;
  readonly source_id?: string;
  readonly evidence_source_id?: string;
  readonly name?: string;
  readonly status?: string;
  readonly created_at?: string;
  readonly executed_at?: string | null;
  readonly registered_artifact_count?: number;
  readonly found_count?: number;
  readonly missing_count?: number;
  readonly targets?: readonly CollectionTarget[];
};

type EvidenceArtifact = {
  readonly id?: string;
  readonly artifact_id?: string;
  readonly source_id?: string;
  readonly plan_id?: string;
  readonly target_id?: string;
  readonly artifact_type?: string;
  readonly type?: string;
  readonly path: string;
  readonly size_bytes?: number;
  readonly sha256?: string;
  readonly parser_hint?: string | Record<string, unknown>;
  readonly registered_at?: string;
};

type EvidenceArtifactsResponse = {
  readonly artifacts: readonly EvidenceArtifact[];
};

type CollectionSnapshot = {
  readonly sources: readonly EvidenceSource[];
  readonly artifacts: readonly EvidenceArtifact[];
};

type Filters = {
  path: string;
  source_artifact: string;
  action: string;
};

const emptyFilters: Filters = { path: "", source_artifact: "", action: "" };

class ApiRequestError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
  }
}

function detailMessage(value: unknown): string | null {
  if (typeof value === "object" && value !== null && "detail" in value) {
    const detail = value.detail;
    return typeof detail === "string" ? detail : null;
  }
  return null;
}

async function parseErrorBody(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch (err) {
    if (err instanceof SyntaxError) {
      return null;
    }
    throw err;
  }
}

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options
  });
  if (!response.ok) {
    const detail = await parseErrorBody(response);
    throw new ApiRequestError(response.status, detailMessage(detail) ?? `Request failed: ${response.status}`);
  }
  const payload: T = await response.json();
  return payload;
}

async function optionalCollectionApi<T>(path: string, fallback: T): Promise<T> {
  try {
    return await api<T>(path);
  } catch (err) {
    if (err instanceof ApiRequestError && err.status === 404) {
      return fallback;
    }
    throw err;
  }
}

async function loadCollectionSnapshot(caseId: string): Promise<CollectionSnapshot> {
  const [sources, artifacts] = await Promise.all([
    loadEvidenceSources(caseId),
    loadEvidenceArtifacts(caseId)
  ]);
  return { sources, artifacts };
}

async function loadEvidenceSources(caseId: string): Promise<readonly EvidenceSource[]> {
  try {
    return await api<readonly EvidenceSource[]>(`/cases/${caseId}/evidence-sources`);
  } catch (err) {
    if (err instanceof ApiRequestError && err.status === 404) {
      return optionalCollectionApi<readonly EvidenceSource[]>(`/cases/${caseId}/sources`, []);
    }
    throw err;
  }
}

async function loadEvidenceArtifacts(caseId: string): Promise<readonly EvidenceArtifact[]> {
  try {
    const response = await api<EvidenceArtifactsResponse>(`/cases/${caseId}/evidence-artifacts`);
    return response.artifacts;
  } catch (err) {
    if (err instanceof ApiRequestError && err.status === 404) {
      return optionalCollectionApi<readonly EvidenceArtifact[]>(`/cases/${caseId}/artifacts`, []);
    }
    throw err;
  }
}

async function createEvidenceSource(caseId: string, rootPath: string): Promise<EvidenceSource> {
  const sourceType = "mounted_windows_directory";
  const body = JSON.stringify({
    name: "Mounted Windows evidence",
    source_type: sourceType,
    root_path: rootPath,
    path: rootPath
  });
  try {
    return await api<EvidenceSource>(`/cases/${caseId}/evidence-sources`, { method: "POST", body });
  } catch (err) {
    if (err instanceof ApiRequestError && err.status === 404) {
      return api<EvidenceSource>(`/cases/${caseId}/sources`, { method: "POST", body });
    }
    throw err;
  }
}

async function createCollectionPlan(caseId: string, sourceId: string): Promise<CollectionPlan> {
  let plan: CollectionPlan;
  try {
    plan = await api<CollectionPlan>(`/cases/${caseId}/collection-plans`, {
      method: "POST",
      body: JSON.stringify({
        name: "NTFS triage plan",
        evidence_source_id: sourceId,
        source_id: sourceId
      })
    });
  } catch (err) {
    if (!(err instanceof ApiRequestError) || err.status !== 404) {
      throw err;
    }
    try {
      plan = await api<CollectionPlan>(`/cases/${caseId}/sources/${sourceId}/plans`, { method: "POST" });
    } catch (nextErr) {
      if (!(nextErr instanceof ApiRequestError) || nextErr.status !== 404) {
        throw nextErr;
      }
      plan = await api<CollectionPlan>(`/cases/${caseId}/sources/${sourceId}/plan`, { method: "POST" });
    }
  }

  const currentPlanId = planId(plan);
  const targets = plan.targets ?? (currentPlanId ? await loadCollectionPlanTargets(caseId, currentPlanId) : []);
  return { ...plan, source_id: plan.source_id ?? plan.evidence_source_id ?? sourceId, targets };
}

async function loadCollectionPlanTargets(caseId: string, currentPlanId: string): Promise<readonly CollectionTarget[]> {
  try {
    return await api<readonly CollectionTarget[]>(`/cases/${caseId}/collection-plans/${currentPlanId}/targets`);
  } catch (err) {
    if (!(err instanceof ApiRequestError) || err.status !== 404) {
      throw err;
    }
    try {
      return await api<readonly CollectionTarget[]>(`/cases/${caseId}/plans/${currentPlanId}/targets`);
    } catch (nextErr) {
      if (nextErr instanceof ApiRequestError && nextErr.status === 404) {
        return [];
      }
      throw nextErr;
    }
  }
}

async function executeCollectionPlan(caseId: string, currentPlanId: string): Promise<CollectionPlan> {
  try {
    return await api<CollectionPlan>(`/cases/${caseId}/collection-plans/${currentPlanId}/execute`, { method: "POST" });
  } catch (err) {
    if (!(err instanceof ApiRequestError) || err.status !== 404) {
      throw err;
    }
    return api<CollectionPlan>(`/cases/${caseId}/plans/${currentPlanId}/execute`, { method: "POST" });
  }
}

function sourceId(source: EvidenceSource): string {
  return source.id ?? source.source_id ?? "";
}

function planId(plan: CollectionPlan): string {
  return plan.id ?? plan.plan_id ?? "";
}

function sourcePath(source: EvidenceSource): string {
  return source.root_path ?? source.path ?? "";
}

function targetLabel(target: CollectionTarget): string {
  return target.label ?? target.artifact_type ?? target.type ?? target.relative_path ?? target.resolved_path ?? target.path ?? "Target";
}

function targetPath(target: CollectionTarget): string {
  return target.resolved_path ?? target.path ?? target.relative_path ?? target.reason ?? "Not found";
}

function isFoundTarget(target: CollectionTarget): boolean {
  return target.classification === "found" || target.status === "found" || target.found === true || Boolean(target.resolved_path);
}

function artifactKind(artifact: EvidenceArtifact): string {
  return artifact.artifact_type ?? artifact.type ?? parserHintLabel(artifact.parser_hint) ?? "artifact";
}

function artifactId(artifact: EvidenceArtifact): string {
  return artifact.id ?? artifact.artifact_id ?? artifact.path;
}

function parserHintLabel(value: string | Record<string, unknown> | undefined): string | null {
  if (value === undefined) {
    return null;
  }
  if (typeof value === "string") {
    return value;
  }
  if ("parser" in value && typeof value.parser === "string") {
    return value.parser;
  }
  if ("type" in value && typeof value.type === "string") {
    return value.type;
  }
  return JSON.stringify(value);
}

function formatBytes(size: number | undefined): string {
  if (size === undefined) {
    return "unknown size";
  }
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

export function App() {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>("");
  const [images, setImages] = useState<ImageRecord[]>([]);
  const [sources, setSources] = useState<readonly EvidenceSource[]>([]);
  const [selectedSourceId, setSelectedSourceId] = useState<string>("");
  const [collectionPlan, setCollectionPlan] = useState<CollectionPlan | null>(null);
  const [artifacts, setArtifacts] = useState<readonly EvidenceArtifact[]>([]);
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<TimelineEvent | null>(null);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [lastRun, setLastRun] = useState<AnalysisRun | null>(null);
  const [filters, setFilters] = useState<Filters>(emptyFilters);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>("");
  const [caseForm, setCaseForm] = useState({ name: "", examiner: "", description: "" });
  const [imagePath, setImagePath] = useState("");
  const [sourcePathValue, setSourcePathValue] = useState("");

  const selectedCase = cases.find((item) => item.id === selectedCaseId) ?? null;
  const selectedSource = sources.find((source) => sourceId(source) === selectedSourceId) ?? null;
  const planTargets = collectionPlan?.targets ?? [];
  const foundTargets = planTargets.filter(isFoundTarget);
  const missingTargets = planTargets.filter((target) => !isFoundTarget(target));
  const currentPlanId = collectionPlan ? planId(collectionPlan) : "";
  const hasAnalysisInput = images.length > 0 || artifacts.length > 0;
  const selectedEventIds = useMemo(() => new Set(recommendations.flatMap((item) => item.evidence_event_ids)), [recommendations]);

  useEffect(() => {
    refreshCases();
  }, []);

  useEffect(() => {
    if (!selectedCaseId) {
      setImages([]);
      setSources([]);
      setSelectedSourceId("");
      setCollectionPlan(null);
      setArtifacts([]);
      setEvents([]);
      setRecommendations([]);
      setReports([]);
      setSelectedEvent(null);
      return;
    }
    setSources([]);
    setSelectedSourceId("");
    setCollectionPlan(null);
    setArtifacts([]);
    refreshCaseData(selectedCaseId);
  }, [selectedCaseId]);

  async function runTask(task: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await task();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function refreshCases() {
    await runTask(async () => {
      const loaded = await api<CaseRecord[]>("/cases");
      setCases(loaded);
      if (!selectedCaseId && loaded.length > 0) {
        setSelectedCaseId(loaded[0].id);
      }
    });
  }

  function updateSelectedSource(loadedSources: readonly EvidenceSource[]) {
    setSelectedSourceId((current) => {
      if (current && loadedSources.some((source) => sourceId(source) === current)) {
        return current;
      }
      const firstSource = loadedSources[0];
      return firstSource ? sourceId(firstSource) : "";
    });
  }

  async function refreshCaseData(caseId = selectedCaseId) {
    if (!caseId) return;
    await runTask(async () => {
      const [loadedImages, timeline, recs, loadedReports, collection] = await Promise.all([
        api<ImageRecord[]>(`/cases/${caseId}/images`),
        loadTimeline(caseId, filters),
        api<{ recommendations: Recommendation[] }>(`/cases/${caseId}/recommendations`),
        api<Report[]>(`/cases/${caseId}/reports`),
        loadCollectionSnapshot(caseId)
      ]);
      setImages(loadedImages);
      setSources(collection.sources);
      setArtifacts(collection.artifacts);
      updateSelectedSource(collection.sources);
      setEvents(timeline.events);
      setRecommendations(recs.recommendations);
      setReports(loadedReports);
      setSelectedEvent((current) => timeline.events.find((event) => event.id === current?.id) ?? timeline.events[0] ?? null);
    });
  }

  async function loadTimeline(caseId: string, activeFilters: Filters) {
    const query = new URLSearchParams();
    query.set("limit", "500");
    if (activeFilters.path) query.set("path", activeFilters.path);
    if (activeFilters.source_artifact) query.set("source_artifact", activeFilters.source_artifact);
    if (activeFilters.action) query.set("action", activeFilters.action);
    return api<{ events: TimelineEvent[]; total: number }>(`/cases/${caseId}/timeline?${query.toString()}`);
  }

  async function createCase(event: FormEvent) {
    event.preventDefault();
    await runTask(async () => {
      const created = await api<CaseRecord>("/cases", {
        method: "POST",
        body: JSON.stringify(caseForm)
      });
      setCaseForm({ name: "", examiner: "", description: "" });
      setCases((current) => [created, ...current]);
      setSelectedCaseId(created.id);
    });
  }

  async function registerImage(event: FormEvent) {
    event.preventDefault();
    if (!selectedCaseId) return;
    await runTask(async () => {
      await api<ImageRecord>(`/cases/${selectedCaseId}/images`, {
        method: "POST",
        body: JSON.stringify({ path: imagePath })
      });
      setImagePath("");
      await refreshCaseData(selectedCaseId);
      await refreshCases();
    });
  }

  async function registerSource(event: FormEvent) {
    event.preventDefault();
    if (!selectedCaseId) return;
    await runTask(async () => {
      const created = await createEvidenceSource(selectedCaseId, sourcePathValue);
      const collection = await loadCollectionSnapshot(selectedCaseId);
      const loadedSources = collection.sources.length > 0 ? collection.sources : [created];
      setSourcePathValue("");
      setSources(loadedSources);
      setArtifacts(collection.artifacts);
      setSelectedSourceId(sourceId(created) || (loadedSources[0] ? sourceId(loadedSources[0]) : ""));
      setCollectionPlan(null);
    });
  }

  async function generatePlan() {
    if (!selectedCaseId || !selectedSourceId) return;
    await runTask(async () => {
      setCollectionPlan(await createCollectionPlan(selectedCaseId, selectedSourceId));
    });
  }

  async function executePlan() {
    if (!selectedCaseId || !collectionPlan || !currentPlanId) return;
    await runTask(async () => {
      const executed = await executeCollectionPlan(selectedCaseId, currentPlanId);
      const targets = executed.targets ?? collectionPlan.targets ?? await loadCollectionPlanTargets(selectedCaseId, currentPlanId);
      setCollectionPlan({ ...collectionPlan, ...executed, targets });
      const collection = await loadCollectionSnapshot(selectedCaseId);
      setSources(collection.sources);
      setArtifacts(collection.artifacts);
      updateSelectedSource(collection.sources);
    });
  }

  async function startAnalysis() {
    if (!selectedCaseId) return;
    await runTask(async () => {
      const newestImage = images[0];
      const artifactIds = artifacts.map(artifactId).filter(Boolean);
      const run = await api<AnalysisRun>(`/cases/${selectedCaseId}/analysis`, {
        method: "POST",
        body: JSON.stringify({
          image_id: artifactIds.length > 0 ? undefined : newestImage?.id,
          artifact_ids: artifactIds.length > 0 ? artifactIds : undefined,
          parser_mode: "auto"
        })
      });
      setLastRun(run);
      await refreshCaseData(selectedCaseId);
      await refreshCases();
    });
  }

  async function applyFilters(event: FormEvent) {
    event.preventDefault();
    if (!selectedCaseId) return;
    await runTask(async () => {
      const timeline = await loadTimeline(selectedCaseId, filters);
      setEvents(timeline.events);
      setSelectedEvent(timeline.events[0] ?? null);
    });
  }

  async function createReport(format: "markdown" | "json" | "csv") {
    if (!selectedCaseId) return;
    await runTask(async () => {
      await api<Report>(`/cases/${selectedCaseId}/reports`, {
        method: "POST",
        body: JSON.stringify({ format })
      });
      setReports(await api<Report[]>(`/cases/${selectedCaseId}/reports`));
    });
  }

  return (
    <main className="appShell">
      <header className="topBar">
        <div>
          <p className="eyebrow">Windows NTFS triage</p>
          <h1>Digital Forensic Automation Agent</h1>
        </div>
        <div className="statusStrip" aria-live="polite">
          <span><ShieldCheck size={16} /> Read-only evidence workflow</span>
          <span><Database size={16} /> SQLite provenance</span>
        </div>
      </header>

      {error && (
        <section className="alert" role="alert">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </section>
      )}

      <section className="workspaceGrid">
        <aside className="casePane">
          <PanelTitle icon={<Archive size={18} />} title="Cases" action={
            <IconButton label="Refresh cases" onClick={refreshCases} disabled={busy}>
              <RefreshCw size={16} />
            </IconButton>
          } />

          <form className="stack" onSubmit={createCase}>
            <input placeholder="Case name" value={caseForm.name} onChange={(event) => setCaseForm({ ...caseForm, name: event.target.value })} required />
            <input placeholder="Examiner" value={caseForm.examiner} onChange={(event) => setCaseForm({ ...caseForm, examiner: event.target.value })} />
            <textarea placeholder="Description" value={caseForm.description} onChange={(event) => setCaseForm({ ...caseForm, description: event.target.value })} />
            <button className="primaryButton" disabled={busy}>
              <Plus size={16} /> Create
            </button>
          </form>

          <div className="caseList">
            {cases.map((caseItem) => (
              <button
                key={caseItem.id}
                className={caseItem.id === selectedCaseId ? "caseButton active" : "caseButton"}
                onClick={() => setSelectedCaseId(caseItem.id)}
              >
                <span>{caseItem.name}</span>
                <small>{caseItem.event_count} events · {caseItem.image_count} images</small>
              </button>
            ))}
          </div>
        </aside>

        <section className="mainPane">
          <div className="summaryBand">
            <div>
              <p className="eyebrow">Active case</p>
              <h2>{selectedCase?.name ?? "No case selected"}</h2>
              <p>{selectedCase?.description || "Create or select a case to begin."}</p>
            </div>
            <div className="metrics">
              <Metric label="Images" value={images.length} />
              <Metric label="Artifacts" value={artifacts.length} />
              <Metric label="Events" value={events.length} />
              <Metric label="Reports" value={reports.length} />
            </div>
          </div>

          <section className="toolPanel collectionPanel">
            <PanelTitle icon={<FolderInput size={18} />} title="Source Collection" action={
              <button className="secondaryButton" onClick={() => refreshCaseData()} disabled={busy || !selectedCaseId}>
                <RefreshCw size={16} /> Refresh
              </button>
            } />
            <div className="collectionColumns">
              <div>
                <form className="inlineForm" onSubmit={registerSource}>
                  <input
                    placeholder="Mounted Windows evidence path"
                    value={sourcePathValue}
                    onChange={(event) => setSourcePathValue(event.target.value)}
                    disabled={!selectedCaseId}
                    required
                  />
                  <button className="primaryButton" disabled={busy || !selectedCaseId}>
                    <Plus size={16} /> Register
                  </button>
                </form>
                <div className="sourceList">
                  {sources.map((source) => {
                    const id = sourceId(source);
                    return (
                      <button
                        key={id || sourcePath(source)}
                        className={id === selectedSourceId ? "sourceButton active" : "sourceButton"}
                        onClick={() => setSelectedSourceId(id)}
                        disabled={!id}
                      >
                        <strong>{source.name ?? source.source_type ?? "source"}</strong>
                        <span>{sourcePath(source)}</span>
                      </button>
                    );
                  })}
                  {sources.length === 0 && <p className="emptyText">No sources registered.</p>}
                </div>
              </div>

              <div>
                <div className="planToolbar">
                  <button className="secondaryButton" onClick={generatePlan} disabled={busy || !selectedSource}>
                    <ClipboardList size={16} /> Generate plan
                  </button>
                  <button className="primaryButton" onClick={executePlan} disabled={busy || !currentPlanId}>
                    <Play size={16} /> Execute
                  </button>
                  {collectionPlan && (
                    <span className="statusPill">
                      {collectionPlan.status ?? "planned"} · {foundTargets.length} found · {missingTargets.length} missing
                    </span>
                  )}
                </div>
                <div className="targetColumns">
                  <TargetList title="Found Targets" targets={foundTargets} variant="found" />
                  <TargetList title="Missing Targets" targets={missingTargets} variant="missing" />
                </div>
              </div>

              <div>
                <PanelTitle icon={<PackageCheck size={18} />} title="Artifacts" />
                <div className="artifactList">
                  {artifacts.map((artifact) => (
                    <div className="artifactRow" key={artifactId(artifact)}>
                      <PackageCheck size={16} />
                      <div>
                        <strong>{artifactKind(artifact)}</strong>
                        <span>{artifact.path}</span>
                        <small>
                          {formatBytes(artifact.size_bytes)} · {artifact.sha256 ? artifact.sha256.slice(0, 24) : "hash pending"}
                          {parserHintLabel(artifact.parser_hint) ? ` · ${parserHintLabel(artifact.parser_hint)}` : ""}
                        </small>
                      </div>
                    </div>
                  ))}
                  {artifacts.length === 0 && <p className="emptyText">No artifacts registered.</p>}
                </div>
              </div>
            </div>
          </section>

          <div className="operationsGrid">
            <section className="toolPanel">
              <PanelTitle icon={<HardDrive size={18} />} title="Evidence Image" />
              <form className="inlineForm" onSubmit={registerImage}>
                <input
                  placeholder="Absolute path to E01, dd, img, or raw"
                  value={imagePath}
                  onChange={(event) => setImagePath(event.target.value)}
                  disabled={!selectedCaseId}
                  required
                />
                <button className="primaryButton" disabled={busy || !selectedCaseId}>
                  <Plus size={16} /> Register
                </button>
              </form>
              <div className="imageList">
                {images.map((image) => (
                  <div className="imageRow" key={image.id}>
                    <FileSearch size={16} />
                    <div>
                      <strong>{image.format.toUpperCase()}</strong>
                      <span>{image.path}</span>
                      <code>{image.sha256.slice(0, 24)}...</code>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            <section className="toolPanel">
              <PanelTitle icon={<Play size={18} />} title="Analysis" />
              <button className="wideAction" onClick={startAnalysis} disabled={busy || !selectedCaseId || !hasAnalysisInput}>
                {busy ? <Loader2 className="spin" size={18} /> : <Play size={18} />}
                Run NTFS timeline analysis
              </button>
              {lastRun && (
                <div className="runStatus">
                  <strong>{lastRun.status}</strong>
                  <span>{lastRun.event_count} events · {lastRun.parser_mode}</span>
                  {lastRun.warning && <p>{lastRun.warning}</p>}
                  {lastRun.warnings?.map((warning) => (
                    <p key={`${warning.code}-${warning.artifact_id ?? warning.artifact_type ?? warning.message}`}>
                      {warning.code}: {warning.message}
                    </p>
                  ))}
                </div>
              )}
            </section>
          </div>

          <section className="timelineSection">
            <PanelTitle icon={<FileClock size={18} />} title="Timeline" action={
              <button className="secondaryButton" onClick={() => setFilters(emptyFilters)}>
                <ListRestart size={16} /> Reset
              </button>
            } />
            <form className="filterBar" onSubmit={applyFilters}>
              <label>
                <Filter size={16} />
                <input placeholder="Path contains" value={filters.path} onChange={(event) => setFilters({ ...filters, path: event.target.value })} />
              </label>
              <input placeholder="Source artifact" value={filters.source_artifact} onChange={(event) => setFilters({ ...filters, source_artifact: event.target.value })} />
              <input placeholder="Action" value={filters.action} onChange={(event) => setFilters({ ...filters, action: event.target.value })} />
              <button className="secondaryButton" disabled={busy || !selectedCaseId}>
                <Filter size={16} /> Apply
              </button>
            </form>

            <div className="timelineGrid">
              <div className="eventTable" role="table" aria-label="Timeline events">
                <div className="eventHeader" role="row">
                  <span>Time</span>
                  <span>Action</span>
                  <span>Artifact</span>
                  <span>Path</span>
                  <span>Confidence</span>
                </div>
                {events.map((event) => (
                  <button
                    className={selectedEvent?.id === event.id ? "eventRow active" : "eventRow"}
                    key={event.id}
                    onClick={() => setSelectedEvent(event)}
                    role="row"
                  >
                    <span>{event.timestamp ?? "unknown"}</span>
                    <span>{event.action}</span>
                    <span>{event.source_artifact}</span>
                    <span className={selectedEventIds.has(event.id) ? "evidencePath marked" : "evidencePath"}>{event.path}</span>
                    <span>{Math.round(event.confidence * 100)}%</span>
                  </button>
                ))}
              </div>

              <aside className="evidencePanel">
                <PanelTitle icon={<FileSearch size={18} />} title="Evidence" />
                {selectedEvent ? (
                  <div className="evidenceBody">
                    <h3>{selectedEvent.action}</h3>
                    <p>{selectedEvent.path}</p>
                    <dl>
                      <dt>Artifact</dt><dd>{selectedEvent.source_artifact}</dd>
                      <dt>Record</dt><dd>{selectedEvent.record_id}</dd>
                      <dt>Event ID</dt><dd><code>{selectedEvent.id}</code></dd>
                    </dl>
                    <pre>{JSON.stringify({ provenance: selectedEvent.provenance, attributes: selectedEvent.attributes }, null, 2)}</pre>
                  </div>
                ) : (
                  <p className="emptyText">No timeline event selected.</p>
                )}
              </aside>
            </div>
          </section>

          <section className="bottomGrid">
            <div className="toolPanel">
              <PanelTitle icon={<Bot size={18} />} title="Grounded Recommendations" />
              <div className="recommendationList">
                {recommendations.map((recommendation) => (
                  <article key={recommendation.title} className="recommendation">
                    <h3>{recommendation.title}</h3>
                    <p>{recommendation.rationale}</p>
                    <small>{recommendation.evidence_event_ids.length} evidence links</small>
                  </article>
                ))}
              </div>
            </div>

            <div className="toolPanel">
              <PanelTitle icon={<FileDown size={18} />} title="Reports" />
              <div className="reportActions">
                <button className="secondaryButton" onClick={() => createReport("markdown")} disabled={!selectedCaseId}>
                  <FileDown size={16} /> Markdown
                </button>
                <button className="secondaryButton" onClick={() => createReport("csv")} disabled={!selectedCaseId}>
                  <FileDown size={16} /> CSV
                </button>
                <button className="secondaryButton" onClick={() => createReport("json")} disabled={!selectedCaseId}>
                  <FileDown size={16} /> JSON
                </button>
              </div>
              <div className="reportList">
                {reports.map((report) => (
                  <div className="reportRow" key={report.id}>
                    <strong>{report.format}</strong>
                    <span>{report.event_count} events</span>
                    <code>{report.path}</code>
                  </div>
                ))}
              </div>
            </div>
          </section>
        </section>
      </section>
    </main>
  );
}

function TargetList({ title, targets, variant }: { title: string; targets: readonly CollectionTarget[]; variant: "found" | "missing" }) {
  const Icon = variant === "found" ? CheckCircle2 : XCircle;
  return (
    <div className="targetList">
      <div className="targetListHeader">
        <Icon size={16} />
        <span>{title}</span>
      </div>
      {targets.map((target, index) => (
        <div className={`targetRow ${variant}`} key={target.id ?? target.target_id ?? `${targetLabel(target)}-${index}`}>
          <div>
            <strong>{targetLabel(target)}</strong>
            <span>{targetPath(target)}</span>
          </div>
          {parserHintLabel(target.parser_hint) && <code>{parserHintLabel(target.parser_hint)}</code>}
        </div>
      ))}
      {targets.length === 0 && <p className="emptyText">No {variant} targets.</p>}
    </div>
  );
}

function PanelTitle({ icon, title, action }: { icon: ReactNode; title: string; action?: ReactNode }) {
  return (
    <div className="panelTitle">
      <div>{icon}<span>{title}</span></div>
      {action}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="metric">
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function IconButton({ label, onClick, disabled, children }: { label: string; onClick: () => void; disabled?: boolean; children: ReactNode }) {
  return (
    <button className="iconButton" aria-label={label} title={label} onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}
