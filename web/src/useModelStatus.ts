import { useEffect, useState } from "react";
import { api } from "./api";

/**
 * Why runs are unavailable, or null when a trained model is ready (or the
 * status is not known yet). Re-checked whenever the window regains focus,
 * since training happens in a terminal outside the dashboard.
 */
export function useModelStatus(): string | null {
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const check = () => {
      api
        .health()
        .then((h) => {
          if (!cancelled) setMessage(h.model_ready ? null : h.model_message);
        })
        .catch(() => {
          // backend unreachable: run attempts will surface the real error
        });
    };

    check();
    window.addEventListener("focus", check);
    return () => {
      cancelled = true;
      window.removeEventListener("focus", check);
    };
  }, []);

  return message;
}
