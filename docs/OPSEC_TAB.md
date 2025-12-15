## OpSec Tab (GUI)

This page documents the **OpSec** tab in the RedBofAnalizer GUI.  
It explains what is analyzed, how the score is calculated, and how to interpret the findings for a given BOF.

---

## Overview

The OpSec tab provides a **static operational security assessment** of a BOF based on its **imported APIs**.

It focuses on:

- **API OpSec classification** (per‑API risk)
- **Risky API combinations** (multi‑API patterns)
- **Suspicious patterns** (higher‑level signals)
- **Overall OpSec score (0–100)** and **recommendations**
- **Related views**: compatibility and calling‑convention analysis

It does **not** run the BOF or monitor live behavior. All results are derived from parsing the BOF and examining its imports.

---

## Data Source and Scope

- The analyzer inspects the **import table** of the BOF.
- All non‑`Beacon` APIs are analyzed; `Beacon` APIs are treated as generally safe and excluded from OpSec risk calculations.
- Each API is looked up in an internal database that assigns:
  - **Risk category**
  - **Description** (why it may be noisy or suspicious)
  - **Detection vectors** (ETW, process monitoring, network monitoring, registry monitoring, etc.)
- Unknown APIs (not in the database) are conservatively treated as **medium‑risk**.

This is a **static OpSec model**, best used as an early warning system and design aid rather than a guarantee of stealth.

---

## Layout of the OpSec Tab

The OpSec tab is split into three main sections:

1. **OpSec Analysis**
2. **Compatibility Analysis**
3. **Calling Convention Analysis**

All three are read‑only views driven by the current analysis results for the loaded BOF.

### 1. OpSec Analysis Section

This section contains the **core OpSec information**.

#### OpSec Score

- Displayed at the top as **“OpSec Score: X/100”**.
- **Higher is better** (stealthier / less noisy).
- Color coding:
  - **Green**: score ≥ 70
  - **Yellow**: 40–69
  - **Red**: < 40

#### API Classifications

This table shows **each imported API** and its **OpSec classification**.

- **Columns**
  - **API**: Imported function name (e.g. `CreateRemoteThread`).
  - **Category**: One of:
    - **LowRisk** – Standard operations, relatively low detection concern.
    - **MediumRisk** – Potentially detectable or somewhat suspicious.
    - **HighRisk** – Clearly suspicious or commonly abused by offensive tools.
    - **CriticalRisk** – Very likely to be flagged by AV/EDR/HIPS.
  - **Description**: Short explanation of why the API is classified at that level.

- **Filters**
  - **Filter by name**: Text box to filter APIs by substring (case‑insensitive).
  - **Filter by risk**: Dropdown to limit the view to a specific risk category or show all.
  - **Clear Filters**: Resets both filters.

If an API is unknown to the internal database, it is listed as **medium‑risk** with a description like:

> `Unknown API: <name>`

#### Risky API Combinations

This section lists **multi‑API patterns** that are known to be **particularly noisy or suspicious**:

1. **Process Injection Pattern**
   - APIs: `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`
   - Risk: **CriticalRisk**
   - Description: Classic remote process injection technique.
   - Recommendation: Consider alternative techniques or stronger OpSec measures.

2. **Token Manipulation Pattern**
   - APIs: `OpenProcessToken` + `DuplicateTokenEx` + `SetThreadToken`
   - Risk: **HighRisk**
   - Description: Token manipulation chain for privilege escalation / impersonation.
   - Recommendation: Monitor token operations and consider logging or alternative approaches.

3. **Unhooking Pattern**
   - APIs: `NtProtectVirtualMemory` + `NtWriteVirtualMemory`
   - Risk: **HighRisk**
   - Description: Memory protection changes combined with direct memory writes (often used for unhooking).
   - Recommendation: Direct syscall‑style unhooking can bypass API hooks but is highly detectable.

4. **Anti‑Debugging Pattern**
   - APIs: `IsDebuggerPresent` + `CheckRemoteDebuggerPresent`
   - Risk: **MediumRisk**
   - Description: Multiple anti‑debugging checks.
   - Recommendation: Consider less noisy anti‑debugging techniques when OpSec is critical.

Each combination is displayed with:

- Risk level (colored)
- Short description
- List of APIs involved
- Recommendation text

#### Suspicious Patterns

This section aggregates **higher‑level OpSec signals** derived from the imports:

- **DirectSyscall**
  - Trigger: `NtCreateThreadEx` or `NtWriteVirtualMemory`.
  - Severity: **HighRisk**.
  - Meaning: Direct syscalls to bypass API hooks; easier to spot in ETW and telemetry.
  - Recommendation: Prefer indirect syscalls or more subtle techniques if stealth is a priority.

- **ProcessInjection**
  - Trigger: `CreateRemoteThread` and `WriteProcessMemory`.
  - Severity: **CriticalRisk**.
  - Meaning: Clear process injection behavior.

- **TokenManipulation**
  - Trigger: `OpenProcessToken` and `DuplicateTokenEx`.
  - Severity: **HighRisk**.
  - Meaning: Token / privilege manipulation behavior.

- **Unhooking**
  - Trigger: `NtProtectVirtualMemory` and `NtWriteVirtualMemory`.
  - Severity: **HighRisk**.
  - Meaning: Likely code / hook tampering or unhooking logic.

Each pattern shows:

- Pattern type (e.g. `DirectSyscall`, `ProcessInjection`) and severity (colored)
- Description of why it matters for OpSec
- Optional location (currently not populated; reserved for future enhancements)

---

### 2. Compatibility Analysis Section

Below the OpSec analysis, the tab also shows **compatibility information** for the BOF:

- **Compatible with**: Lists Cobalt Strike versions that are considered compatible.
- **Version‑Specific Features**: Shows which features require newer CS versions.
- **Compatibility Issues**:
  - Filterable by severity (Info, Warning, Error).
  - Each issue includes affected versions and a recommendation.
- **Recommendations**: Summary of steps to improve or ensure compatibility.

This is a GUI view of the same compatibility analysis described in `ADVANCED_FEATURES.md`.

---

### 3. Calling Convention Analysis Section

The final section summarizes **calling convention analysis**:

- **Detected Convention**: The calling convention inferred for the BOF entry point.
- **Issues**:
  - Severity (Info, Warning, Error)
  - Location (symbol / section)
  - Optional “Detected vs Expected” details
- **Recommendations**: Guidance to fix mismatches or unsafe conventions.

This is provided alongside OpSec information to make it easy to check **stealth**, **compatibility**, and **correctness** from a single tab.

---

## OpSec Score Calculation

The **OpSec score** starts at **100** and is reduced according to what is found:

- **Per API classification**
  - LowRisk: −1 point
  - MediumRisk: −5 points
  - HighRisk: −10 points
  - CriticalRisk: −20 points

- **Per risky combination**
  - LowRisk: −5 points
  - MediumRisk: −10 points
  - HighRisk: −15 points
  - CriticalRisk: −25 points

- **Per suspicious pattern**
  - LowRisk: −3 points
  - MediumRisk: −7 points
  - HighRisk: −12 points
  - CriticalRisk: −20 points

The final score is **clamped to 0–100** and then color‑coded in the UI.

If the final score is **below 50**, additional general recommendations are added, such as:

- Review API usage and reduce high‑risk operations.
- Prefer alternative techniques with better OpSec properties.

---

## How to Use the OpSec Tab Effectively

- **Design phase**
  - Use the OpSec tab while iterating on a BOF to quickly see how changes in API usage affect the score and patterns.
  - Prefer lower‑risk APIs or less noisy patterns where possible.

- **Pre‑deployment review**
  - Check that the OpSec score is acceptable for the intended environment.
  - Review any **CriticalRisk** or **HighRisk** APIs and combinations.
  - Confirm that compatibility issues are resolved for the target CS version(s).

- **Triage and comparison**
  - Compare scores and patterns between different BOFs or versions of the same BOF.
  - Use the detailed API and pattern lists to explain why one implementation is more/less stealthy than another.

---

## Related Documentation

- **CLI OpSec / advanced analysis**: `ADVANCED_FEATURES.md` (Enhanced OpSec Analysis section)
- **General GUI overview**: `GUI_GUIDE.md`


