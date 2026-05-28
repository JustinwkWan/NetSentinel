import { useEffect, useState } from "react";
import { api, type PcapInfo } from "../api";

interface Props {
  selected: string | null;
  onSelect: (name: string) => void;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function PcapSelector({ selected, onSelect }: Props) {
  const [pcaps, setPcaps] = useState<PcapInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.listPcaps();
      setPcaps(list);
      if (!selected && list.length > 0) onSelect(list[0].name);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setError(null);
    try {
      const info = await api.uploadPcap(file);
      await refresh();
      onSelect(info.name);
    } catch (err) {
      setError(String(err));
    } finally {
      setUploading(false);
      e.target.value = "";
    }
  };

  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium text-slate-300">PCAP file</label>
      <div className="flex gap-2">
        <select
          className="flex-1 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-cyan-500"
          value={selected ?? ""}
          onChange={(e) => onSelect(e.target.value)}
          disabled={loading || pcaps.length === 0}
        >
          {pcaps.length === 0 && <option>No PCAPs available</option>}
          {pcaps.map((p) => (
            <option key={p.name} value={p.name}>
              {p.name} ({fmtBytes(p.size_bytes)})
            </option>
          ))}
        </select>
        <label className="bg-slate-700 hover:bg-slate-600 border border-slate-600 rounded px-3 py-2 text-sm cursor-pointer">
          {uploading ? "Uploading…" : "Upload"}
          <input
            type="file"
            accept=".pcap,.pcapng"
            className="hidden"
            onChange={onUpload}
            disabled={uploading}
          />
        </label>
      </div>
      {error && <div className="text-rose-400 text-xs">{error}</div>}
    </div>
  );
}
