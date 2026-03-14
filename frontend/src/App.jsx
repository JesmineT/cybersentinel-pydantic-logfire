import { useState, useRef, useEffect } from "react"

const SEVERITY_STYLES = {
  CRITICAL: { color: "#ef4444", bg: "#450a0a", border: "#ef444440" },
  HIGH:     { color: "#f97316", bg: "#431407", border: "#f9731640" },
  MEDIUM:   { color: "#eab308", bg: "#422006", border: "#eab30840" },
  LOW:      { color: "#3b82f6", bg: "#1e3a5f", border: "#3b82f640" },
  INFO:     { color: "#64748b", bg: "#1e293b", border: "#64748b40" },
}

function SeverityBadge({ level }) {
  const s = SEVERITY_STYLES[level] || SEVERITY_STYLES.INFO
  return (
    <span style={{
      background: s.bg,
      color: s.color,
      border: `1px solid ${s.border}`,
      borderRadius: 4,
      padding: "2px 10px",
      fontSize: 11,
      fontWeight: 700,
      fontFamily: "monospace",
      letterSpacing: "0.08em",
    }}>
      {level}
    </span>
  )
}

function ThreatReport({ report }) {
  return (
    <div style={{
      background: "#0a0f1e",
      border: `1px solid ${SEVERITY_STYLES[report.severity]?.color}40`,
      borderLeft: `3px solid ${SEVERITY_STYLES[report.severity]?.color}`,
      borderRadius: 8,
      padding: 16,
      marginTop: 8,
    }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <SeverityBadge level={report.severity} />
        <span style={{ color: "#e2e8f0", fontWeight: 600, fontSize: 13, fontFamily: "monospace" }}>
          {report.incident_id}
        </span>
        {report.escalate_to_human && (
          <span style={{
            background: "#450a0a", color: "#f87171",
            border: "1px solid #f8717140",
            borderRadius: 4, padding: "2px 8px",
            fontSize: 10, fontWeight: 700,
          }}>
            ⚠ ESCALATE
          </span>
        )}
      </div>

      {/* Summary */}
      <p style={{ color: "#cbd5e1", fontSize: 13, lineHeight: 1.6, marginBottom: 12 }}>
        {report.summary}
      </p>

      {/* IOCs */}
      {report.iocs?.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ color: "#475569", fontSize: 10, letterSpacing: "0.1em", marginBottom: 6, textTransform: "uppercase" }}>
            Indicators of Compromise
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {report.iocs.map((ioc, i) => (
              <span key={i} style={{
                background: "#1e293b",
                border: "1px solid #334155",
                borderRadius: 4,
                padding: "3px 10px",
                fontSize: 11,
                fontFamily: "monospace",
                color: "#94a3b8",
              }}>
                <span style={{ color: "#475569" }}>[{ioc.type}]</span> {ioc.value}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Affected Assets */}
      <div style={{ marginBottom: 12 }}>
        <div style={{ color: "#475569", fontSize: 10, letterSpacing: "0.1em", marginBottom: 6, textTransform: "uppercase" }}>
          Affected Assets
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {report.affected_assets?.map((a, i) => (
            <span key={i} style={{
              background: "#1e293b", border: "1px solid #334155",
              borderRadius: 4, padding: "3px 10px",
              fontSize: 11, fontFamily: "monospace", color: "#94a3b8"
            }}>
              {a}
            </span>
          ))}
        </div>
      </div>

      {/* Recommended Actions */}
      <div>
        <div style={{ color: "#475569", fontSize: 10, letterSpacing: "0.1em", marginBottom: 6, textTransform: "uppercase" }}>
          Recommended Actions
        </div>
        {report.recommended_actions?.map((action, i) => (
          <div key={i} style={{
            display: "flex", gap: 8, alignItems: "flex-start",
            color: "#cbd5e1", fontSize: 12, lineHeight: 1.6, marginBottom: 4
          }}>
            <span style={{ color: "#22c55e", flexShrink: 0 }}>→</span>
            {action}
          </div>
        ))}
      </div>
    </div>
  )
}

function TypingIndicator() {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 0" }}>
      {[0, 1, 2].map(i => (
        <span key={i} style={{
          width: 6, height: 6, borderRadius: "50%",
          background: "#3b82f6", display: "inline-block",
          animation: `bounce 1.2s infinite ${i * 0.2}s`,
        }} />
      ))}
      <span style={{ color: "#475569", fontSize: 12, marginLeft: 4 }}>
        SENTINEL investigating...
      </span>
    </div>
  )
}

export default function App() {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState("")
  const [loading, setLoading] = useState(false)
  const [sessionId, setSessionId] = useState(null)
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages, loading])

  const send = async () => {
    const text = input.trim()
    if (!text || loading) return

    setMessages(prev => [...prev, { role: "user", content: text }])
    setInput("")
    setLoading(true)

    try {
      const res = await fetch("http://localhost:8000/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: text,
          session_id: sessionId,       // null on first message
        })
      })

      const data = await res.json()
      setSessionId(data.session_id)   // save session for next message

      setMessages(prev => [...prev, {
        role: "agent",
        answer: data.report?.answer,
        report: data.report?.report,
      }])

    } catch (err) {
      setMessages(prev => [...prev, {
        role: "error",
        content: `Error: ${err.message}`
      }])
    } finally {
      setLoading(false)
    }
  }

  const EXAMPLES = [
    "Investigate IP 10.0.0.99 — outbound traffic on port 4444",
    "Workstation 192.168.1.105 is running encoded PowerShell",
    "Unusual traffic from 192.168.99.5 to multiple external IPs",
  ]

  return (
    <>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #030712; color: #e2e8f0; font-family: system-ui, sans-serif; }
        @keyframes bounce {
          0%, 80%, 100% { transform: translateY(0); }
          40% { transform: translateY(-6px); }
        }
        textarea:focus { outline: none; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 2px; }
      `}</style>

      <div style={{ display: "flex", flexDirection: "column", height: "100vh" }}>

        {/* Header */}
        <div style={{
          background: "#0a0f1e",
          borderBottom: "1px solid #1a2444",
          padding: "14px 24px",
          display: "flex",
          alignItems: "center",
          gap: 12,
          flexShrink: 0,
        }}>
          <div style={{
            width: 32, height: 32,
            background: "linear-gradient(135deg, #3b82f6, #1d4ed8)",
            borderRadius: 8, display: "flex",
            alignItems: "center", justifyContent: "center",
            fontSize: 16,
          }}>
            ⬡
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: 16, letterSpacing: "0.05em" }}>
              CYBERSENTINEL
            </div>
            <div style={{ color: "#475569", fontSize: 10, letterSpacing: "0.1em" }}>
              ST ENGINEERING · SOC THREAT TRIAGE AGENT
            </div>
          </div>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
            <span style={{
              width: 7, height: 7, borderRadius: "50%",
              background: "#22c55e", display: "inline-block"
            }} />
            <span style={{ color: "#475569", fontSize: 11, fontFamily: "monospace" }}>
              {sessionId ? `SESSION ${sessionId.slice(0, 8).toUpperCase()}` : "NO SESSION"}
            </span>
          </div>
        </div>

        {/* Messages */}
        <div style={{ flex: 1, overflowY: "auto", padding: "20px 24px" }}>

          {messages.length === 0 && (
            <div style={{ textAlign: "center", marginTop: 60 }}>
              <div style={{ color: "#1e3a5f", fontSize: 48, marginBottom: 16 }}>⬡</div>
              <div style={{ color: "#334155", fontSize: 14, marginBottom: 24 }}>
                Describe a threat or suspicious activity to begin triage
              </div>
              <div style={{ display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap" }}>
                {EXAMPLES.map((ex, i) => (
                  <button key={i} onClick={() => setInput(ex)} style={{
                    background: "#0a0f1e",
                    border: "1px solid #1a2444",
                    borderRadius: 20,
                    padding: "6px 14px",
                    color: "#475569",
                    fontSize: 11,
                    cursor: "pointer",
                    fontFamily: "monospace",
                  }}>
                    {ex.slice(0, 40)}…
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((msg, i) => (
            <div key={i} style={{ marginBottom: 16 }}>

              {msg.role === "user" && (
                <div style={{ display: "flex", justifyContent: "flex-end" }}>
                  <div style={{
                    background: "#1e3a5f",
                    border: "1px solid #3b82f640",
                    borderRadius: "12px 12px 2px 12px",
                    padding: "10px 14px",
                    maxWidth: "70%",
                    fontSize: 13,
                    lineHeight: 1.6,
                    color: "#e2e8f0",
                  }}>
                    {msg.content}
                  </div>
                </div>
              )}

              {msg.role === "agent" && (
                <div style={{ maxWidth: "90%" }}>
                  <div style={{ color: "#3b82f6", fontSize: 11, fontFamily: "monospace", marginBottom: 4 }}>
                    SENTINEL
                  </div>

                  {/* Short answer for follow-up questions */}
                  {msg.answer && (
                    <div style={{
                      color: "#cbd5e1", fontSize: 13, lineHeight: 1.6,
                      padding: "8px 0",
                    }}>
                      {msg.answer}
                    </div>
                  )}

                  {/* Full report for new investigations */}
                  {msg.report && <ThreatReport report={msg.report} />}
                </div>
              )}

              {msg.role === "error" && (
                <div style={{
                  background: "#450a0a", border: "1px solid #f8717140",
                  borderRadius: 8, padding: "10px 14px",
                  color: "#f87171", fontSize: 12, fontFamily: "monospace"
                }}>
                  {msg.content}
                </div>
              )}

            </div>
          ))}

          {loading && (
            <div style={{ maxWidth: "90%" }}>
              <div style={{ color: "#3b82f6", fontSize: 11, fontFamily: "monospace", marginBottom: 4 }}>
                SENTINEL
              </div>
              <TypingIndicator />
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <div style={{
          borderTop: "1px solid #1a2444",
          padding: "16px 24px",
          background: "#0a0f1e",
          display: "flex",
          gap: 10,
          flexShrink: 0,
        }}>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault()
                send()
              }
            }}
            placeholder="Describe the incident or suspicious activity…"
            rows={2}
            style={{
              flex: 1,
              background: "#0f172a",
              border: "1px solid #1a2444",
              borderRadius: 8,
              padding: "10px 14px",
              color: "#e2e8f0",
              fontSize: 13,
              resize: "none",
              fontFamily: "system-ui, sans-serif",
              lineHeight: 1.5,
            }}
          />
          <button
            onClick={send}
            disabled={loading || !input.trim()}
            style={{
              background: loading || !input.trim()
                ? "#1e293b"
                : "linear-gradient(135deg, #3b82f6, #1d4ed8)",
              border: "none",
              borderRadius: 8,
              padding: "0 20px",
              color: loading || !input.trim() ? "#475569" : "white",
              fontWeight: 700,
              fontSize: 13,
              cursor: loading || !input.trim() ? "not-allowed" : "pointer",
              letterSpacing: "0.05em",
            }}
          >
            {loading ? "…" : "TRIAGE"}
          </button>
        </div>

      </div>
    </>
  )
}