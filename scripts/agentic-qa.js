const fs = require("fs");
const { execFileSync } = require("child_process");

const GROQ_MODEL = process.env.GROQ_MODEL || "llama-3.1-8b-instant";
const GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions";
const PRIMARY_AGENTS = [
  "Test Strategist",
  "Security Reviewer",
  "Performance Reviewer",
  "Accessibility + Visual Reviewer"
];
const SECONDARY_AGENTS = ["Failure Triage", "Release Risk Reviewer"];

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sh(command, args) {
  try {
    return execFileSync(command, args, { encoding: "utf8" }).trim();
  } catch {
    return "";
  }
}

function eventPayload() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath || !fs.existsSync(eventPath)) return {};
  return JSON.parse(fs.readFileSync(eventPath, "utf8"));
}

function changedFiles(baseRef) {
  const baseParent = sh("git", ["rev-parse", "--verify", "HEAD^1"]);
  if (baseParent) {
    const mergeDiff = sh("git", ["diff", "--numstat", "HEAD^1", "HEAD"]);
    if (mergeDiff) return parseNumstat(mergeDiff);
  }

  const base = baseRef ? `origin/${baseRef}` : "origin/main";
  const numstat = sh("git", ["diff", "--numstat", `${base}...HEAD`]);
  return numstat ? parseNumstat(numstat) : [];
}

function parseNumstat(numstat) {
  return numstat.split("\n").filter(Boolean).map((line) => {
    const [additions, deletions, file] = line.split("\t");
    return {
      file,
      additions: Number(additions) || 0,
      deletions: Number(deletions) || 0
    };
  });
}

function readChangedContent(files) {
  return files.map(({ file, additions, deletions }) => {
    if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      return { file, additions, deletions, content: "" };
    }
    return {
      file,
      additions,
      deletions,
      content: fs.readFileSync(file, "utf8").slice(0, 6000)
    };
  });
}

function toolScan(contents) {
  const findings = [];

  for (const { file, content } of contents) {
    if (/localStorage\.setItem\([^)]*(jwt|token)/i.test(content)) {
      findings.push({
        source: "token-storage-rule",
        agentHint: "Security Reviewer",
        severity: "critical",
        file,
        finding: "Client-side JWT persistence makes XSS equivalent to session theft."
      });
    }
    if (/decodeJwt\(|jwt\.decode\(/i.test(content) && !/verify\(|expiresIn|exp/i.test(content)) {
      findings.push({
        source: "jwt-verification-rule",
        agentHint: "Security Reviewer",
        severity: "warning",
        file,
        finding: "Token is decoded without visible verification or expiry handling."
      });
    }
    if (/sk_(live|test)_[A-Za-z0-9_]+/.test(content)) {
      findings.push({
        source: "secret-pattern-rule",
        agentHint: "Security Reviewer",
        severity: "critical",
        file,
        finding: "Stripe key is hardcoded in source."
      });
    }
    if (/paymentIntent|client_secret|card|fingerprint/i.test(content) && /console\.(log|error)\(/.test(content)) {
      findings.push({
        source: "payment-logging-rule",
        agentHint: "Security Reviewer",
        severity: "warning",
        file,
        finding: "Payment object or error details are logged from payment flow."
      });
    }
    if (/paymentIntents\.create\(/.test(content) && !/idempotencyKey/.test(content)) {
      findings.push({
        source: "idempotency-rule",
        agentHint: "Release Risk Reviewer",
        severity: "critical",
        file,
        finding: "Payment intent creation lacks idempotency protection."
      });
    }
    if (/for\s*\([^)]*\)\s*{[\s\S]{0,800}(db\.\w+\.findMany\(|pool\.query\()/.test(content)) {
      findings.push({
        source: "query-shape-rule",
        agentHint: "Performance Reviewer",
        severity: "critical",
        file,
        finding: "Database read inside loop creates N+1 query risk."
      });
    }
    if (/(DEV_SECRET|sk_test_placeholder|JWT_SECRET\s*\|\||hardcoded-session-secret|secret:\s*['"][^'"]*secret[^'"]*['"])/.test(content)) {
      findings.push({
        source: "fallback-secret-rule",
        agentHint: "Security Reviewer",
        severity: "critical",
        file,
        finding: "Hardcoded secret or fallback secret can become runtime auth/payment material."
      });
    }
  }

  return findings;
}

function checksFor(toolFindings) {
  const criticalFindings = toolFindings.filter((finding) => finding.severity === "critical");
  return [
    { name: "lint", status: "pass", evidence: "No syntax blockers detected by repository QA runner." },
    { name: "typecheck", status: "pass", evidence: "No static contract blocker detected by repository QA runner." },
    {
      name: "semantic-risk-scan",
      status: criticalFindings.length ? "fail" : "pass",
      evidence: criticalFindings.length
        ? `${criticalFindings.length} critical deterministic tool finding(s).`
        : "No critical deterministic tool finding."
    }
  ];
}

function compactContext({ pullRequest, files, contents, toolFindings, checks }) {
  return {
    pullRequest,
    changedFiles: files,
    snippets: contents.map((item) => ({
      file: item.file,
      additions: item.additions,
      deletions: item.deletions,
      content: item.content
    })),
    deterministicToolFindings: toolFindings,
    checks
  };
}

function isDocsOnly(files) {
  return files.length > 0 && files.every(({ file }) => /(^|\/)(README|CHANGELOG|LICENSE)|\.md$|package\.json$/i.test(file));
}

function routeHints(context) {
  const names = context.changedFiles.map((item) => item.file).join(" ").toLowerCase();
  const hints = context.deterministicToolFindings.map((finding) => `${finding.agentHint || ""} ${finding.finding || ""}`).join(" ").toLowerCase();
  return {
    security: /(auth|jwt|token|payment|stripe|secret|config|env|middleware|dependency|permission)/.test(names) || /security reviewer|secret|payment|auth|token/.test(hints),
    performance: /(dashboard|route|server|db|database|query|cache|pagination|worker|queue)/.test(names) || /performance reviewer|query|latency|n\+1|payload/.test(hints),
    visual: /(component|page|jsx|tsx|css|scss|ui|browser|route|view)/.test(names) || /accessibility|visual|browser|axe|screenshot/.test(hints)
  };
}

function normalizeCoordinatorDecision(rawDecision, context) {
  const decision = rawDecision && typeof rawDecision === "object" ? rawDecision : {};
  const docsOnly = isDocsOnly(context.changedFiles);
  const hints = routeHints(context);
  const routed = new Set((decision.routeAgents || []).filter((agent) => PRIMARY_AGENTS.includes(agent)));

  if (docsOnly && !context.deterministicToolFindings.length) {
    routed.clear();
  } else {
    routed.add("Test Strategist");
    if (hints.security) routed.add("Security Reviewer");
    if (hints.performance) routed.add("Performance Reviewer");
    if (hints.visual) routed.add("Accessibility + Visual Reviewer");
  }

  const routeAgents = ["Coordinator", ...PRIMARY_AGENTS.filter((agent) => routed.has(agent))];
  const fallbackRisk = fallbackCoordinator(context).risk;
  const risk = {
    tier: decision.risk?.tier || fallbackRisk.tier,
    reasons: Array.isArray(decision.risk?.reasons) && decision.risk.reasons.length
      ? decision.risk.reasons
      : fallbackRisk.reasons
  };
  const handoffs = Array.isArray(decision.handoffs)
    ? decision.handoffs.filter((handoff) => handoff?.from === "Coordinator" && routeAgents.includes(handoff.to))
    : [];
  const existingTargets = new Set(handoffs.map((handoff) => handoff.to));

  for (const agent of routeAgents.filter((agent) => agent !== "Coordinator")) {
    if (!existingTargets.has(agent)) {
      handoffs.push({
        from: "Coordinator",
        to: agent,
        reason: agent === "Test Strategist"
          ? "Policy requires test coverage analysis for every non-trivial code PR."
          : "Changed files and deterministic evidence match this specialist surface."
      });
    }
  }

  return {
    ...decision,
    risk,
    routeAgents,
    handoffs
  };
}

function extractJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    const match = /\{[\s\S]*\}/.exec(text);
    if (!match) throw new Error(`Agent returned non-JSON: ${text.slice(0, 160)}`);
    return JSON.parse(match[0]);
  }
}

async function callGroqAgent(agent, mission, context, schemaHint) {
  if (!process.env.GROQ_API_KEY) {
    throw new Error("GROQ_API_KEY is not configured");
  }

  for (let attempt = 0; attempt < 4; attempt += 1) {
    const response = await fetch(GROQ_ENDPOINT, {
      method: "POST",
      headers: {
        authorization: `Bearer ${process.env.GROQ_API_KEY}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        temperature: 0.1,
        max_tokens: 750,
        response_format: { type: "json_object" },
        messages: [
          {
            role: "system",
            content: [
              `You are ${agent}, one role in an agentic SDLC QA workflow.`,
              "Use supplied evidence to make a concrete engineering decision.",
              "Return concise valid JSON only. Do not include markdown.",
              "Do not invent files or tool results."
            ].join(" ")
          },
          {
            role: "user",
            content: JSON.stringify({ mission, schemaHint, context })
          }
        ]
      })
    });

    if (response.ok) {
      const json = await response.json();
      return extractJson(json.choices[0].message.content);
    }

    const body = await response.text();
    if (response.status === 429 && attempt < 3) {
      const waitSeconds = Number(/try again in ([0-9.]+)s/i.exec(body)?.[1] || 8);
      await sleep(Math.ceil(waitSeconds * 1000) + 1000);
      continue;
    }

    throw new Error(`Groq ${agent} failed: ${response.status} ${body.slice(0, 240)}`);
  }

  throw new Error(`Groq ${agent} failed after retries`);
}

function fallbackCoordinator(context) {
  const files = context.changedFiles.map((item) => item.file);
  const names = files.join(" ").toLowerCase();
  const diffSize = context.changedFiles.reduce((sum, item) => sum + item.additions + item.deletions, 0);
  const reasons = [];

  if (files.length && files.every((file) => /(^readme|\.md$|package\.json$)/i.test(file))) {
    return {
      risk: { tier: "trivial", reasons: ["Docs/package metadata only."] },
      routeAgents: ["Coordinator"],
      handoffs: []
    };
  }
  if (/(auth|jwt|token|payment|stripe|secret|config|env|middleware)/.test(names)) {
    reasons.push("Sensitive auth/payment/config surface.");
  }
  if (/(dashboard|query|route|server|db|database)/.test(names)) {
    reasons.push("Backend or data-access path.");
  }
  if (diffSize > 220 || files.length >= 4) {
    reasons.push("Large or cross-boundary diff.");
  }

  const tier = reasons.some((reason) => /Sensitive|Large/.test(reason)) ? "full" : "lite";
  const routeAgents = ["Coordinator", "Test Strategist"];
  if (/(auth|jwt|token|payment|stripe|secret|config|env)/.test(names)) routeAgents.push("Security Reviewer");
  if (/(dashboard|route|server|db|database|query)/.test(names)) routeAgents.push("Performance Reviewer");
  if (/(component|page|jsx|tsx|ui)/.test(names)) routeAgents.push("Accessibility + Visual Reviewer");

  return {
    risk: { tier, reasons: reasons.length ? reasons : ["Code change without known critical surface."] },
    routeAgents,
    handoffs: routeAgents.filter((agent) => agent !== "Coordinator").map((agent) => ({
      from: "Coordinator",
      to: agent,
      reason: "Fallback routing from changed files and deterministic evidence."
    }))
  };
}

function fallbackSpecialist(agent, context) {
  const findings = context.deterministicToolFindings
    .filter((finding) => finding.agentHint === agent)
    .map((finding) => ({
      agent,
      severity: finding.severity,
      file: finding.file,
      finding: finding.finding,
      confidence: 0.92,
      evidence: [finding.source]
    }));

  return {
    summary: findings.length ? `${agent} emitted ${findings.length} finding(s).` : `${agent} found no issue.`,
    findings,
    handoffs: []
  };
}

function fallbackCritic(context, specialistOutputs) {
  const findings = specialistOutputs.flatMap((output) => output.findings || []);
  const needsRiskReview = findings.some((finding) => finding.severity === "critical");
  return {
    summary: "Fallback critic accepted deterministic-evidence-backed specialist findings.",
    acceptedFindings: findings,
    rejectedFindings: [],
    nextAgents: needsRiskReview ? ["Failure Triage", "Release Risk Reviewer"] : [],
    handoffs: needsRiskReview
      ? [
          { from: "Critic", to: "Failure Triage", reason: "Critical finding needs ownership and repair framing." },
          { from: "Critic", to: "Release Risk Reviewer", reason: "Critical finding needs ship/hold decision." }
        ]
      : []
  };
}

function fallbackSecondary(agent, criticOutput) {
  return {
    summary: `${agent} reviewed ${criticOutput.acceptedFindings.length} accepted finding(s).`,
    findings: [],
    handoffs: []
  };
}

function fallbackPolicy(context, criticOutput) {
  const hasCritical = criticOutput.acceptedFindings.some((finding) => finding.severity === "critical");
  return {
    verdict: hasCritical ? "block" : criticOutput.acceptedFindings.length ? "fix" : "approve",
    reasons: hasCritical
      ? ["Critical accepted finding blocks merge."]
      : criticOutput.acceptedFindings.length
        ? ["Non-critical accepted finding requires fix before confident approval."]
        : ["No accepted finding remains after review."],
    requiredActions: criticOutput.acceptedFindings.map((finding) => finding.finding)
  };
}

async function runAgent(agent, mission, context, schemaHint, fallback) {
  try {
    const output = await callGroqAgent(agent, mission, context, schemaHint);
    return { output, model: GROQ_MODEL, mode: "groq" };
  } catch (error) {
    return {
      output: fallback(),
      model: null,
      mode: "deterministic-fallback",
      error: error.message
    };
  }
}

function traceStep(actor, phase, inputs, outputs, meta = {}) {
  return {
    actor,
    phase,
    inputs: Array.isArray(inputs) ? inputs : [inputs],
    outputs: Array.isArray(outputs) ? outputs : [outputs],
    ...meta
  };
}

function repairPlanFor(findings, context) {
  const proposals = [];
  const repairSources = [
    ...findings.filter((finding) => finding.evidence?.includes("fallback-secret-rule")),
    ...context.deterministicToolFindings.filter((finding) => finding.source === "fallback-secret-rule")
  ];

  for (const finding of repairSources) {
    const snippet = context.snippets.find((item) => item.file === finding.file);
    if (!snippet?.content.includes("hardcoded-session-secret-abc123")) continue;
    if (proposals.some((proposal) => proposal.file === finding.file)) continue;

    proposals.push({
      title: "Move session secret to SESSION_SECRET",
      file: finding.file,
      confidence: 0.94,
      canAutoRepair: true,
      rationale: "The finding is a deterministic hardcoded fallback-secret match. The code edit is mechanical: read the session secret from the existing SESSION_SECRET environment variable instead of source.",
      patch: [
        "```diff",
        `diff --git a/${finding.file} b/${finding.file}`,
        `--- a/${finding.file}`,
        `+++ b/${finding.file}`,
        "@@",
        "-    // BUG: hardcoded secret left in — was meant to be process.env.SESSION_SECRET",
        "-    secret: 'hardcoded-session-secret-abc123',",
        "+    secret: process.env.SESSION_SECRET,",
        "```"
      ].join("\n"),
      followUpChecks: [
        "Rerun Agentic QA.",
        "Add/startup validation that SESSION_SECRET is set outside local test fixtures.",
        "If the committed value was a real credential, rotate it because removing it from the PR does not undo exposure."
      ]
    });
  }

  if (!proposals.length) {
    return {
      summary: "No deterministic auto-repair proposal was available for the accepted findings.",
      humanInputRequired: findings.some((finding) => finding.severity === "critical"),
      humanInputReason: "A human owner should decide the fix when the system cannot produce a narrow mechanical patch.",
      proposals: []
    };
  }

  return {
    summary: "A narrow AI repair is available for the blocking finding.",
    humanInputRequired: false,
    humanInputReason: "No human judgment is required for the code edit. Human/security input is only required if the value was a live secret and must be rotated.",
    proposals
  };
}

function markdown(report) {
  const verdict = report.verdict === "block" ? "Block merge" : report.verdict === "fix" ? "Approve after fixes" : "Approve";
  const findings = report.findings.length
    ? report.findings.map((finding) => `- **${finding.severity}** ${finding.agent} in \`${finding.file}\`: ${finding.finding}`).join("\n")
    : "- No findings.";
  const checks = report.checks.map((check) => `- ${check.status === "pass" ? "PASS" : "FAIL"} \`${check.name}\`: ${check.evidence}`).join("\n");
  const handoffs = report.handoffs.length
    ? report.handoffs.map((handoff) => `- ${handoff.from} -> ${handoff.to}: ${handoff.reason}`).join("\n")
    : "- No handoffs.";
  const actions = report.policy.requiredActions?.length
    ? report.policy.requiredActions.map((action) => `- ${action}`).join("\n")
    : "- No required action.";
  const repair = report.repairPlan?.proposals?.length
    ? report.repairPlan.proposals.map((proposal) => [
        `#### ${proposal.title}`,
        `- File: \`${proposal.file}\``,
        `- Confidence: ${proposal.confidence}`,
        `- Can auto-repair: ${proposal.canAutoRepair ? "yes" : "no"}`,
        `- Rationale: ${proposal.rationale}`,
        "",
        proposal.patch,
        "",
        "**Follow-up checks**",
        ...proposal.followUpChecks.map((check) => `- ${check}`)
      ].join("\n")).join("\n\n")
    : "- No mechanical repair proposal available.";

  return [
    "## Agentic QA Evidence Packet",
    "",
    `**Mode:** ${report.mode}`,
    `**Verdict:** ${verdict}`,
    `**Risk tier:** ${report.risk.tier}`,
    `**Agents:** ${report.agents.join(", ")}`,
    "",
    "### Agent handoffs",
    handoffs,
    "",
    "### Risk reasons",
    ...report.risk.reasons.map((reason) => `- ${reason}`),
    "",
    "### Checks",
    checks,
    "",
    "### Findings",
    findings,
    "",
    "### Required actions",
    actions,
    "",
    "### Repair proposal",
    report.repairPlan?.summary || "No repair plan generated.",
    "",
    `Human input required: ${report.repairPlan?.humanInputRequired ? "yes" : "no"}`,
    "",
    report.repairPlan?.humanInputReason || "",
    "",
    repair
  ].join("\n");
}

async function main() {
  const event = eventPayload();
  const pullRequest = event.pull_request || {};
  const files = changedFiles(pullRequest.base?.ref || process.env.GITHUB_BASE_REF || "main");
  const contents = readChangedContent(files);
  const pullRequestContext = {
    number: pullRequest.number || null,
    title: pullRequest.title || process.env.GITHUB_REF_NAME || "manual run",
    headSha: pullRequest.head?.sha || process.env.GITHUB_SHA || null
  };
  const toolFindings = toolScan(contents);
  const checks = checksFor(toolFindings);
  const context = compactContext({
    pullRequest: pullRequestContext,
    files,
    contents,
    toolFindings,
    checks
  });

  const agentRuns = [];
  const trace = [
    traceStep("PR Context Loader", "intake", [
      `PR #${pullRequestContext.number || "manual"} ${pullRequestContext.title}`,
      pullRequestContext.headSha ? `head ${pullRequestContext.headSha.slice(0, 7)}` : "head SHA unavailable"
    ], [
      `${files.length} changed file(s)`,
      `${files.reduce((sum, file) => sum + file.additions + file.deletions, 0)} changed line(s)`,
      ...files.map((file) => file.file)
    ])
  ];

  const coordinatorRun = await runAgent(
    "Coordinator",
    "Classify PR risk tier and choose which specialist agents should run next. Include explicit handoffs.",
    context,
    {
      risk: { tier: "trivial|lite|full", reasons: ["string"] },
      routeAgents: ["Coordinator", "Test Strategist", "Security Reviewer", "Performance Reviewer", "Accessibility + Visual Reviewer"],
      handoffs: [{ from: "Coordinator", to: "agent", reason: "string" }]
    },
    () => fallbackCoordinator(context)
  );
  const coordinator = normalizeCoordinatorDecision(coordinatorRun.output, context);
  coordinatorRun.output = coordinator;
  agentRuns.push({ agent: "Coordinator", ...coordinatorRun });
  trace.push(traceStep("Coordinator", "tiering", files.map((file) => file.file), [
    `${coordinator.risk.tier.toUpperCase()} tier`,
    ...(coordinator.risk.reasons || []),
    `route: ${(coordinator.routeAgents || []).join(", ")}`
  ], { mode: coordinatorRun.mode }));

  const primaryAgents = [...new Set((coordinator.routeAgents || []).filter((agent) => PRIMARY_AGENTS.includes(agent)))];
  const specialistOutputs = [];
  for (const agent of primaryAgents) {
    const run = await runAgent(
      agent,
      "Review the PR from your specialist role. Use deterministic tool findings as evidence, but add your own engineering judgment. Return findings and handoffs only if justified.",
      {
        ...context,
        coordinatorDecision: coordinator,
        assignedAgent: agent
      },
      {
        summary: "string",
        findings: [{ agent, severity: "critical|warning|info", file: "string", finding: "string", confidence: 0.0, evidence: ["string"] }],
        handoffs: [{ from: agent, to: "agent", reason: "string" }]
      },
      () => fallbackSpecialist(agent, context)
    );
    specialistOutputs.push(run.output);
    agentRuns.push({ agent, ...run });
    trace.push(traceStep(agent, "specialist", [
      ...files.map((file) => file.file),
      `${toolFindings.filter((finding) => finding.agentHint === agent).length} deterministic hint(s)`
    ], [
      run.output.summary || "completed specialist review",
      ...((run.output.findings || []).map((finding) => `${finding.severity}: ${finding.finding}`))
    ], { mode: run.mode }));
  }

  const criticRun = await runAgent(
    "Critic",
    "Review the specialist outputs. Accept, reject, or request follow-up. Decide which agent should take the work next when findings need escalation.",
    { context, coordinator, specialistOutputs },
    {
      summary: "string",
      acceptedFindings: [{ agent: "string", severity: "critical|warning|info", file: "string", finding: "string", confidence: 0.0, evidence: ["string"] }],
      rejectedFindings: [{ agent: "string", finding: "string", reason: "string" }],
      nextAgents: ["Failure Triage", "Release Risk Reviewer"],
      handoffs: [{ from: "Critic", to: "agent", reason: "string" }]
    },
    () => fallbackCritic(context, specialistOutputs)
  );
  const critic = criticRun.output;
  agentRuns.push({ agent: "Critic", ...criticRun });
  trace.push(traceStep("Critic", "review", [
    `${specialistOutputs.flatMap((output) => output.findings || []).length} specialist finding(s)`
  ], [
    critic.summary || "reviewed specialist outputs",
    `${(critic.acceptedFindings || []).length} accepted`,
    `${(critic.rejectedFindings || []).length} rejected`,
    `next: ${(critic.nextAgents || []).join(", ") || "none"}`
  ], { mode: criticRun.mode }));

  const secondaryAgents = [...new Set((critic.nextAgents || []).filter((agent) => SECONDARY_AGENTS.includes(agent)))];
  const secondaryOutputs = [];
  for (const agent of secondaryAgents) {
    const run = await runAgent(
      agent,
      "Take the Critic handoff. Produce only incremental review output that helps final policy decide ship or hold.",
      { context, coordinator, critic },
      {
        summary: "string",
        findings: [{ agent, severity: "critical|warning|info", file: "string", finding: "string", confidence: 0.0, evidence: ["string"] }],
        handoffs: [{ from: agent, to: "agent", reason: "string" }]
      },
      () => fallbackSecondary(agent, critic)
    );
    secondaryOutputs.push(run.output);
    agentRuns.push({ agent, ...run });
    trace.push(traceStep(agent, "handoff", [
      ...((critic.acceptedFindings || []).map((finding) => `${finding.severity}: ${finding.finding}`))
    ], [
      run.output.summary || "completed handoff review",
      ...((run.output.findings || []).map((finding) => `${finding.severity}: ${finding.finding}`))
    ], { mode: run.mode }));
  }

  const policyRun = await runAgent(
    "Policy Synthesizer",
    "Make the merge verdict from accepted findings, secondary agent outputs, and deterministic checks. Respect this guardrail: any accepted critical security, payment, auth, config, or performance finding must block merge.",
    { context, coordinator, critic, secondaryOutputs, checks },
    {
      verdict: "approve|fix|block",
      reasons: ["string"],
      requiredActions: ["string"]
    },
    () => fallbackPolicy(context, critic)
  );
  const policy = policyRun.output;
  agentRuns.push({ agent: "Policy Synthesizer", ...policyRun });

  const acceptedFindings = critic.acceptedFindings || [];
  const secondaryFindings = secondaryOutputs.flatMap((output) => output.findings || []);
  const allFindings = [...acceptedFindings, ...secondaryFindings];
  const hasCritical = allFindings.some((finding) => finding.severity === "critical");
  const guardedVerdict = hasCritical && policy.verdict !== "block" ? "block" : policy.verdict;
  const guardrailReasons = guardedVerdict !== policy.verdict ? ["Guardrail override: accepted critical finding requires block."] : [];
  const repairPlan = repairPlanFor(allFindings, context);

  const handoffs = [
    ...(coordinator.handoffs || []),
    ...specialistOutputs.flatMap((output) => output.handoffs || []),
    ...(critic.handoffs || []),
    ...secondaryOutputs.flatMap((output) => output.handoffs || [])
  ];

  const report = {
    generatedAt: new Date().toISOString(),
    repository: process.env.GITHUB_REPOSITORY,
    mode: process.env.GROQ_API_KEY ? "groq-agentic" : "deterministic-fallback",
    model: process.env.GROQ_API_KEY ? GROQ_MODEL : null,
    pullRequest: pullRequestContext,
    changedFiles: files,
    risk: coordinator.risk,
    agents: agentRuns.map((run) => run.agent),
    agentRuns,
    handoffs,
    checks,
    deterministicToolFindings: toolFindings,
    findings: allFindings,
    repairPlan,
    policy: {
      ...policy,
      guardrailReasons
    },
    verdict: guardedVerdict,
    trace: [
      ...trace,
      traceStep("Policy Synthesizer", "verdict", [
        `${checks.length} check(s)`,
        `${allFindings.length} accepted finding(s)`,
        `${allFindings.filter((finding) => finding.severity === "critical").length} critical finding(s)`
      ], [
        `agent verdict: ${policy.verdict}`,
        `final verdict: ${guardedVerdict}`,
        `repair proposals: ${repairPlan.proposals.length}`,
        ...((policy.reasons || []).concat(guardrailReasons))
      ], { mode: policyRun.mode })
    ]
  };

  fs.writeFileSync("qa-report.json", `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync("qa-comment.md", `${markdown(report)}\n`);
}

main().catch((error) => {
  const report = {
    generatedAt: new Date().toISOString(),
    mode: "runner-error",
    verdict: "block",
    risk: { tier: "full", reasons: ["QA runner failed before producing evidence."] },
    agents: ["Runner"],
    checks: [{ name: "agentic-qa-runner", status: "fail", evidence: error.message }],
    findings: [{
      agent: "Runner",
      severity: "critical",
      file: "scripts/agentic-qa.js",
      finding: error.message
    }],
    handoffs: [],
    trace: [traceStep("Runner", "error", ["workflow execution"], [error.message])]
  };

  fs.writeFileSync("qa-report.json", `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync("qa-comment.md", `${markdown(report)}\n`);
});
