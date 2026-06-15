import {
  AlertTriangle,
  Archive,
  Bot,
  Database,
  FileClock,
  FileDown,
  FileSearch,
  Filter,
  HardDrive,
  ListRestart,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  ShieldCheck
} from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";

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
  event_count: number;
  tool_versions: Record<string, unknown>;
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

type Filters = {
  path: string;
  source_artifact: string;
  action: string;
};

const emptyFilters: Filters = { path: "", source_artifact: "", action: "" };

async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(detail.detail ?? `Request failed: ${response.status}`);
  }
  return response.json();
}

export function App() {
  const [cases, setCases] = useState<CaseRecord[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>("");
  const [images, setImages] = useState<ImageRecord[]>([]);
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

  const selectedCase = cases.find((item) => item.id === selectedCaseId) ?? null;
  const selectedEventIds = useMemo(() => new Set(recommendations.flatMap((item) => item.evidence_event_ids)), [recommendations]);

  useEffect(() => {
    refreshCases();
  }, []);

  useEffect(() => {
    if (!selectedCaseId) {
      setImages([]);
      setEvents([]);
      setRecommendations([]);
      setReports([]);
      setSelectedEvent(null);
      return;
    }
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

  async function refreshCaseData(caseId = selectedCaseId) {
    if (!caseId) return;
    await runTask(async () => {
      const [loadedImages, timeline, recs, loadedReports] = await Promise.all([
        api<ImageRecord[]>(`/cases/${caseId}/images`),
        loadTimeline(caseId, filters),
        api<{ recommendations: Recommendation[] }>(`/cases/${caseId}/recommendations`),
        api<Report[]>(`/cases/${caseId}/reports`)
      ]);
      setImages(loadedImages);
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

  async function startAnalysis() {
    if (!selectedCaseId) return;
    await runTask(async () => {
      const newestImage = images[0];
      const run = await api<AnalysisRun>(`/cases/${selectedCaseId}/analysis`, {
        method: "POST",
        body: JSON.stringify({ image_id: newestImage?.id, parser_mode: "auto" })
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
              <Metric label="Events" value={events.length} />
              <Metric label="Reports" value={reports.length} />
            </div>
          </div>

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
              <button className="wideAction" onClick={startAnalysis} disabled={busy || images.length === 0}>
                {busy ? <Loader2 className="spin" size={18} /> : <Play size={18} />}
                Run NTFS timeline analysis
              </button>
              {lastRun && (
                <div className="runStatus">
                  <strong>{lastRun.status}</strong>
                  <span>{lastRun.event_count} events · {lastRun.parser_mode}</span>
                  {lastRun.warning && <p>{lastRun.warning}</p>}
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

function PanelTitle({ icon, title, action }: { icon: React.ReactNode; title: string; action?: React.ReactNode }) {
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

function IconButton({ label, onClick, disabled, children }: { label: string; onClick: () => void; disabled?: boolean; children: React.ReactNode }) {
  return (
    <button className="iconButton" aria-label={label} title={label} onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}

