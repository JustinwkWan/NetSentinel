import { useState } from "react";
import { PcapSelector } from "./components/PcapSelector";
import { RunControls } from "./components/RunControls";
import { RunStatusPanel } from "./components/RunStatusPanel";
import { RunHistory } from "./components/RunHistory";
import { LiveCapturePanel } from "./components/LiveCapturePanel";
import { LocalBrowser } from "./components/LocalBrowser";

function App() {
  const [selectedPcap, setSelectedPcap] = useState<string | null>(null);
  const [currentJobId, setCurrentJobId] = useState<string | null>(null);
  const [historyRefresh, setHistoryRefresh] = useState(0);

  const onRunStarted = (jobId: string) => {
    setCurrentJobId(jobId);
    setHistoryRefresh((n) => n + 1);
  };

  return (
    <div className="min-h-full">
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-3 flex items-center gap-3">
          <div className="text-cyan-400 text-lg font-semibold tracking-tight">
            NetSentinel
          </div>
          <div className="text-slate-500 text-xs">
            AI network security agent
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-6 grid grid-cols-1 lg:grid-cols-[20rem_1fr] gap-6">
        <aside className="space-y-6">
          <section className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 space-y-4">
            <h2 className="text-sm font-semibold text-slate-200">New run</h2>
            <PcapSelector selected={selectedPcap} onSelect={setSelectedPcap} />
            <RunControls pcapName={selectedPcap} onRunStarted={onRunStarted} />
          </section>

          <LocalBrowser onRunStarted={onRunStarted} />

          <LiveCapturePanel
            onActivity={() => setHistoryRefresh((n) => n + 1)}
          />

          <section className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-semibold text-slate-200">History</h2>
            <RunHistory
              currentJobId={currentJobId}
              onSelect={setCurrentJobId}
              refreshKey={historyRefresh}
            />
          </section>
        </aside>

        <section className="bg-slate-900/60 border border-slate-800 rounded-lg p-5 min-h-[24rem]">
          <RunStatusPanel jobId={currentJobId} />
        </section>
      </main>
    </div>
  );
}

export default App;
