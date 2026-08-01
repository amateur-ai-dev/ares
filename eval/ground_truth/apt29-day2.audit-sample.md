# Day 2 — check 10 entries from the answer key

> Each entry below shows **two values, A and B**. Your only job is to say
> whether they are identical. Nothing else on the page needs checking, and
> no security knowledge is required — it is string comparison.
>
> Tick one box per entry by putting an `x` in the brackets: `- [x]`.
>
> These values are read straight out of the raw log at the line numbers shown,
> so they are what the log actually says, not a summary of it.

Sample: 10 of 22 scoreable edges, `random.Random(20260731)`, seed fixed so this is reproducible.

---
## GT-D2-001 — powershell.exe started certutil.exe

From attack step `11.A`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  powershell.exe   (log line 106653)
    its own ID:
    {8320f18b-275a-5ead-7305-000000000400}

B.  certutil.exe   (log line 108092)
    the ID of whatever started it:
    {8320f18b-275a-5ead-7305-000000000400}
```

**Are A and B identical?** If yes, powershell.exe started certutil.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-02 03:55:06  UTICA.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" Get-Content '.\2016_United_States_presidential_election_-_Wi
B: 2020-05-02 03:55:26  UTICA.dmevals.local
   C:\Windows\System32\certutil.exe
   "C:\windows\system32\certutil.exe" -decode blob C:\Users\dschrute\AppData\Roaming\Microsoft\kxwn.lock
```

The ADS-launched PowerShell stager spawned certutil.exe to decode kxwn.lock.

</details>

**Your verdict:**

- [ ] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D2-009 — powershell.exe is what opened this network connection

From attack step `16.C`. Relation claimed: `PROCESS_OPENED_CONNECTION`.

### Compare these two values

```text
A.  powershell.exe   (log line 149014)
    its own ID:
    {8320f18b-280e-5ead-8d05-000000000400}

B.  powershell.exe   (log line 301567)
    the ID of the process that opened the connection:
    {8320f18b-280e-5ead-8d05-000000000400}
```

**Are A and B identical?** If yes, powershell.exe is what opened this network connection — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-02 03:58:06  UTICA.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   "PowerShell.exe" -exec bypass -Noninteractive -windowstyle hidden -e WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQB
B: 2020-05-02 04:02:45  UTICA.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The elevated PowerShell process opened the planned WinRM connection to NEWYORK (10.0.0.4:5985).

</details>

**Your verdict:**

- [ ] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D2-008 — powershell.exe wrote the file that m.exe later ran

From attack step `14.B`. Relation claimed: `WROTE_PATH_BEFORE_EXECUTION`.

### Compare these two values

```text
A.  powershell.exe   (log line 156859)
    the file it wrote:
    C:\Windows\System32\m.exe

B.  m.exe   (log line 156910)
    the file that was then run:
    C:\Windows\System32\m.exe
```

**Are A and B identical?** If yes, powershell.exe wrote the file that m.exe later ran — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-02 03:59:10  UTICA.dmevals.local
   C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe
B: 2020-05-02 03:59:10  UTICA.dmevals.local
   C:\Windows\System32\m.exe
   "m.exe" privilege::debug sekurlsa::logonpasswords exit
```

The credential-dump script wrote m.exe, then executed the same path one second later.

</details>

**Your verdict:**

- [ ] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D2-019 — rundll32.exe is what opened this network connection

From attack step `20.A`. Relation claimed: `PROCESS_OPENED_CONNECTION`.

### Compare these two values

```text
A.  rundll32.exe   (log line 481915)
    its own ID:
    {8320f18b-2bcf-5ead-d200-000000000500}

B.  rundll32.exe   (log line 523326)
    the ID of the process that opened the connection:
    {8320f18b-2bcf-5ead-d200-000000000500}
```

**Are A and B identical?** If yes, rundll32.exe is what opened this network connection — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-02 04:14:07  UTICA.dmevals.local
   C:\Windows\System32\rundll32.exe
   "C:\Windows\System32\rundll32.exe" C:\Users\dschrute\AppData\Roaming\Microsoft\kxwn.lock,VoidFunc
B: 2020-05-02 04:18:18  UTICA.dmevals.local
   C:\Windows\System32\rundll32.exe
```

The Run-key DLL's rundll32 host opened the callback connection to 192.168.0.4:443.

</details>

**Your verdict:**

- [ ] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D2-020 — powershell.exe started klist.exe

From attack step `20.B`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  powershell.exe   (log line 459373)
    its own ID:
    {8320f18b-2b9a-5ead-9400-000000000500}

B.  klist.exe   (log line 514976)
    the ID of whatever started it:
    {8320f18b-2b9a-5ead-9400-000000000500}
```

**Are A and B identical?** If yes, powershell.exe started klist.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-02 04:13:14  UTICA.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQBQAG8Aa
B: 2020-05-02 04:16:19  UTICA.dmevals.local
   C:\Windows\System32\klist.exe
   "C:\windows\system32\klist.exe" purge
```

The SYSTEM callback PowerShell spawned klist.exe for the planned ticket-cache purge.

</details>

**Your verdict:**

- [ ] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D2-004 — control.exe started powershell.exe

From attack step `14.A`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  control.exe   (log line 148617)
    its own ID:
    {8320f18b-280d-5ead-8b05-000000000400}

B.  powershell.exe   (log line 149014)
    the ID of whatever started it:
    {8320f18b-280d-5ead-8b05-000000000400}
```

**Are A and B identical?** If yes, control.exe started powershell.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-02 03:58:05  UTICA.dmevals.local
   C:\Windows\System32\control.exe
   "C:\Windows\System32\control.exe"  /name Microsoft.BackupAndRestoreCenter
B: 2020-05-02 03:58:06  UTICA.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   "PowerShell.exe" -exec bypass -Noninteractive -windowstyle hidden -e WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQB
```

control.exe from the UAC-bypass chain spawned the hidden PoshC2 PowerShell stager.

</details>

**Your verdict:**

- [ ] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D2-016 — powershell.exe is what opened this network connection

From attack step `20.A`. Relation claimed: `PROCESS_OPENED_CONNECTION`.

### Compare these two values

```text
A.  powershell.exe   (log line 454847)
    its own ID:
    {8320f18b-2b86-5ead-7b00-000000000500}

B.  powershell.exe   (log line 461591)
    the ID of the process that opened the connection:
    {8320f18b-2b86-5ead-7b00-000000000500}
```

**Are A and B identical?** If yes, powershell.exe is what opened this network connection — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-02 04:12:55  UTICA.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQBQAG8Aa
B: 2020-05-02 04:13:17  UTICA.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

One login-triggered SYSTEM stager opened the PoshC2 callback to 192.168.0.4:443.

</details>

**Your verdict:**

- [ ] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D2-015 — WmiPrvSE.exe started powershell.exe

From attack step `20.A`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  WmiPrvSE.exe   (log line 414125)
    its own ID:
    {8320f18b-2b7b-5ead-6200-000000000500}

B.  powershell.exe   (log line 459373)
    the ID of whatever started it:
    {8320f18b-2b7b-5ead-6200-000000000500}
```

**Are A and B identical?** If yes, WmiPrvSE.exe started powershell.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-02 04:12:43  UTICA.dmevals.local
   C:\Windows\System32\wbem\WmiPrvSE.exe
   C:\windows\system32\wbem\wmiprvse.exe -Embedding
B: 2020-05-02 04:13:14  UTICA.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   powershell -exec bypass -Noninteractive -windowstyle hidden -e WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQBQAG8Aa
```

The same WMI subscription spawned a third observed SYSTEM PowerShell stager.

</details>

**Your verdict:**

- [ ] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D2-003 — certutil.exe wrote the file that rundll32.exe later ran

From attack step `11.A, 20.A`. Relation claimed: `WROTE_PATH_BEFORE_EXECUTION`.

### Compare these two values

```text
A.  certutil.exe   (log line 108343)
    the file it wrote:
    C:\Users\dschrute\AppData\Roaming\Microsoft\kxwn.lock

B.  rundll32.exe   (log line 482136)
    the file that was then run:
    C:\Windows\System32\rundll32.exe
```

**Are A and B identical?** If yes, certutil.exe wrote the file that rundll32.exe later ran — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-02 03:55:27  UTICA.dmevals.local
   C:\windows\system32\certutil.exe
B: 2020-05-02 04:14:09  UTICA.dmevals.local
   C:\Windows\System32\rundll32.exe
```

certutil wrote kxwn.lock; after logon, rundll32.exe invoked that same path as a DLL.

</details>

**Your verdict:**

- [ ] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D2-006 — powershell.exe and powershell.exe ran in the same logged-in session

From attack step `14.A, 14.B`. Relation claimed: `SAME_SESSION`.

### Compare these two values

```text
A.  powershell.exe   (log line 149014)
    its logon session:
    0xa65039

B.  powershell.exe   (log line 156212)
    its logon session:
    0xa65039
```

**Are A and B identical?** If yes, powershell.exe and powershell.exe ran in the same logged-in session — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-02 03:58:06  UTICA.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   "PowerShell.exe" -exec bypass -Noninteractive -windowstyle hidden -e WwBTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBlAHIAdgBpAGMAZQB
B: 2020-05-02 03:59:09  UTICA.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   powershell.exe -enc JAB3AGMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7
```

The elevated callback and WMI credential-dump PowerShell action share dschrute's non-well-known interactive session; this proves only the named session relation.

</details>

**Your verdict:**

- [ ] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure

