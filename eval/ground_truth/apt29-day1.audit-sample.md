# Day 1 — check 10 entries from the answer key

> Each entry below shows **two values, A and B**. Your only job is to say
> whether they are identical. Nothing else on the page needs checking, and
> no security knowledge is required — it is string comparison.
>
> Tick one box per entry by putting an `x` in the brackets: `- [x]`.
>
> These values are read straight out of the raw log at the line numbers shown,
> so they are what the log actually says, not a summary of it.

Sample: 10 of 36 scoreable edges, `random.Random(20260731)`, seed fixed so this is reproducible.

---
## GT-D1-002 — â€®cod.3aka3.scr is what opened this network connection

From attack step `1.A`. Relation claimed: `PROCESS_OPENED_CONNECTION`.

### Compare these two values

```text
A.  â€®cod.3aka3.scr   (log line 373)
    its own ID:
    {47ab858c-e13c-5eac-a903-000000000400}

B.  â€®cod.3aka3.scr   (log line 567)
    the ID of the process that opened the connection:
    {47ab858c-e13c-5eac-a903-000000000400}
```

**Are A and B identical?** If yes, â€®cod.3aka3.scr is what opened this network connection — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-01 22:55:56  SCRANTON.dmevals.local
   C:\ProgramData\victim\â€®cod.3aka3.scr
   "C:\ProgramData\victim\â€®cod.3aka3.scr" /S
B: 2020-05-01 22:56:00  SCRANTON.dmevals.local
   C:\ProgramData\victim\â€®cod.3aka3.scr
```

The payload process opened 10.0.1.4:1234 to 192.168.0.5:1234.

</details>

**Your verdict:**

- [x] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D1-018 — powershell.exe started accessChk.exe

From attack step `6.A`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  powershell.exe   (log line 27185)
    its own ID:
    {47ab858c-e23d-5eac-c603-000000000400}

B.  accessChk.exe   (log line 52209)
    the ID of whatever started it:
    {47ab858c-e23d-5eac-c603-000000000400}
```

**Are A and B identical?** If yes, powershell.exe started accessChk.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-01 23:00:13  SCRANTON.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   powershell.exe
B: 2020-05-01 23:04:34  SCRANTON.dmevals.local
   C:\Program Files\SysinternalsSuite\accessChk.exe
   "C:\Program Files\SysinternalsSuite\accesschk.exe"
```

</details>

**Your verdict:**

- [x] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D1-016 — powershell.exe started sdelete64.exe

From attack step `4.B`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  powershell.exe   (log line 27185)
    its own ID:
    {47ab858c-e23d-5eac-c603-000000000400}

B.  sdelete64.exe   (log line 48961)
    the ID of whatever started it:
    {47ab858c-e23d-5eac-c603-000000000400}
```

**Are A and B identical?** If yes, powershell.exe started sdelete64.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-01 23:00:13  SCRANTON.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   powershell.exe
B: 2020-05-01 23:03:14  SCRANTON.dmevals.local
   C:\Program Files\SysinternalsSuite\sdelete64.exe
   "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\Users\pbeesly\AppData\Roaming\Draft.Zip
```

</details>

**Your verdict:**

- [x] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D1-034 — powershell.exe started hostui.exe

From attack step `10.B`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  powershell.exe   (log line 183900)
    its own ID:
    {47ab858c-e72f-5eac-f400-000000000500}

B.  hostui.exe   (log line 185073)
    the ID of whatever started it:
    {47ab858c-e72f-5eac-f400-000000000500}
```

**Are A and B identical?** If yes, powershell.exe started hostui.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-01 23:21:19  SCRANTON.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas"
B: 2020-05-01 23:21:27  SCRANTON.dmevals.local
   C:\Windows\System32\hostui.exe
   "C:\Windows\System32\hostui.exe" 
```

</details>

**Your verdict:**

- [x] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D1-008 — control.exe started powershell.exe

From attack step `3.B`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  control.exe   (log line 6747)
    its own ID:
    {47ab858c-e1e3-5eac-b603-000000000400}

B.  powershell.exe   (log line 6930)
    the ID of whatever started it:
    {47ab858c-e1e3-5eac-b603-000000000400}
```

**Are A and B identical?** If yes, control.exe started powershell.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-01 22:58:43  SCRANTON.dmevals.local
   C:\Windows\System32\control.exe
   "C:\Windows\System32\control.exe"  /name Microsoft.BackupAndRestoreCenter
B: 2020-05-01 22:58:44  SCRANTON.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $
```

</details>

**Your verdict:**

- [x] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D1-033 — cmd.exe started powershell.exe

From attack step `10.B`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  cmd.exe   (log line 183718)
    its own ID:
    {47ab858c-e72f-5eac-f200-000000000500}

B.  powershell.exe   (log line 183900)
    the ID of whatever started it:
    {47ab858c-e72f-5eac-f200-000000000500}
```

**Are A and B identical?** If yes, cmd.exe started powershell.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-01 23:21:19  SCRANTON.dmevals.local
   C:\Windows\System32\cmd.exe
   C:\windows\system32\cmd.exe /c ""C:\Windows\System32\hostui.bat" "
B: 2020-05-01 23:21:19  SCRANTON.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas"
```

</details>

**Your verdict:**

- [x] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D1-029 — python.exe started cmd.exe

From attack step `9.C`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  python.exe   (log line 102644)
    its own ID:
    {5aa8ec29-e5b8-5eac-7903-000000000400}

B.  cmd.exe   (log line 112664)
    the ID of whatever started it:
    {5aa8ec29-e5b8-5eac-7903-000000000400}
```

**Are A and B identical?** If yes, python.exe started cmd.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-01 23:15:04  NASHUA.dmevals.local
   C:\Windows\Temp\python.exe
   "C:\Windows\Temp\python.exe" 
B: 2020-05-01 23:16:40  NASHUA.dmevals.local
   C:\Windows\System32\cmd.exe
   C:\windows\system32\cmd.exe
```

</details>

**Your verdict:**

- [x] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D1-005 — cmd.exe started powershell.exe

From attack step `3.A`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  cmd.exe   (log line 3876)
    its own ID:
    {47ab858c-e188-5eac-b003-000000000400}

B.  powershell.exe   (log line 3965)
    the ID of whatever started it:
    {47ab858c-e188-5eac-b003-000000000400}
```

**Are A and B identical?** If yes, cmd.exe started powershell.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-01 22:57:12  SCRANTON.dmevals.local
   C:\Windows\System32\cmd.exe
   "C:\windows\system32\cmd.exe"
B: 2020-05-01 22:57:15  SCRANTON.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   powershell
```

</details>

**Your verdict:**

- [x] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D1-012 — powershell.exe is what opened this network connection

From attack step `3.B`. Relation claimed: `PROCESS_OPENED_CONNECTION`.

### Compare these two values

```text
A.  powershell.exe   (log line 6930)
    its own ID:
    {47ab858c-e1e4-5eac-b803-000000000400}

B.  powershell.exe   (log line 7665)
    the ID of the process that opened the connection:
    {47ab858c-e1e4-5eac-b803-000000000400}
```

**Are A and B identical?** If yes, powershell.exe is what opened this network connection — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-01 22:58:44  SCRANTON.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $
B: 2020-05-01 22:58:46  SCRANTON.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

The UAC-bypass PowerShell process opened 10.0.1.4:443 to 192.168.0.5:443.

</details>

**Your verdict:**

- [x] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure


---

## GT-D1-035 — hostui.exe started powershell.exe

From attack step `10.B`. Relation claimed: `SPAWNED`.

### Compare these two values

```text
A.  hostui.exe   (log line 185073)
    its own ID:
    {47ab858c-e737-5eac-fa00-000000000500}

B.  powershell.exe   (log line 185395)
    the ID of whatever started it:
    {47ab858c-e737-5eac-fa00-000000000500}
```

**Are A and B identical?** If yes, hostui.exe started powershell.exe — the edge is right. Ignore every other value in the log; this one comparison is the whole check.

<details><summary>More context, only if you want it</summary>

```text
A: 2020-05-01 23:21:27  SCRANTON.dmevals.local
   C:\Windows\System32\hostui.exe
   "C:\Windows\System32\hostui.exe" 
B: 2020-05-01 23:21:27  SCRANTON.dmevals.local
   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\Javasoft' 'value Supplement' | Invoke-Expression"
```

</details>

**Your verdict:**

- [x] MATCH — the two values are identical
- [ ] NO MATCH — they differ
- [ ] unsure

