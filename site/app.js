"use strict";

// Illustrations of documented rules, not results from a live scan.
const examples = {
  required: {
    impact: "Breaking",
    className: "breaking",
    rule: "MP-DIFF-102",
    heading: "Existing calls may stop working.",
    explanation:
      "A call that only supplies component no longer satisfies the tool’s required arguments.",
    before: '"required": ["component"]',
    after: '"required": ["component", "region"]',
    outcome: "Fails at the default breaking threshold",
  },
  description: {
    impact: "Risky",
    className: "risky",
    rule: "MP-DIFF-003",
    heading: "The model may choose differently.",
    explanation:
      "The arguments still work, but a new description can change when a model selects this tool. Review its affected scenarios.",
    before: '"description": "Read component status."',
    after: '"description": "Read current or historical status."',
    outcome: "Fails when the threshold is set to risky",
  },
  optional: {
    impact: "Compatible",
    className: "compatible",
    rule: "MP-DIFF-104",
    heading: "Existing arguments still fit.",
    explanation:
      "Adding an optional detail flag preserves the existing required arguments. The schema change is classified as compatible.",
    before: '"properties": {"component": {"type": "string"}}',
    after:
      '"properties": {\n  "component": {"type": "string"},\n  "detail": {"type": "boolean"}\n}',
    outcome: "Passes the default breaking threshold",
  },
};

document.querySelectorAll("[data-example]").forEach((button) => {
  button.addEventListener("click", () => {
    const example = examples[button.dataset.example];
    document.querySelectorAll("[data-example]").forEach((choice) => {
      const selected = choice === button;
      choice.classList.toggle("selected", selected);
      choice.setAttribute("aria-pressed", String(selected));
    });
    for (const field of [
      "impact",
      "heading",
      "explanation",
      "before",
      "after",
      "rule",
      "outcome",
    ]) {
      document.getElementById(`demo-${field}`).textContent = example[field];
    }
    document.getElementById("demo-impact").className =
      `pill ${example.className}`;
  });
});

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const status = document.getElementById(button.dataset.status);
    try {
      await navigator.clipboard.writeText(
        document.getElementById(button.dataset.copy).textContent,
      );
      status.textContent =
        button.dataset.copy === "install-code"
          ? "Commands copied. Replace the example URL with your own endpoint."
          : "Evidence-site commands copied. Review the package before running them.";
      button.textContent = "Copied ✓";
      window.setTimeout(() => {
        button.textContent = "Copy commands";
      }, 2200);
    } catch {
      status.textContent =
        "Clipboard access is unavailable. Select the commands and copy them manually.";
    }
  });
});
