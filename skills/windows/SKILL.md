---
name: windows
description: >
  Complete Windows osquery table catalog (118 tables) and schemas for diagnosing
  Windows operating system issues, including system and hardware info, physical
  memory, processes, services, scheduled tasks, Windows Event Logs, Registry,
  WMI persistence, drivers, patches, disks/volumes, BitLocker, Windows Security
  Center, Windows Firewall, networking, user logon sessions, and forensic execution
  artifacts.
license: Apache-2.0
---

# Windows Diagnostic Skill (`osquery` Schema & Playbook Reference)

> *Table schemas and descriptions adapted from [osquery](https://github.com/osquery/osquery) specifications (licensed under Apache-2.0).*

This skill provides the complete, authoritative catalog of **118 `osquery` tables available on Windows** (53 Windows-only tables in `specs/windows/*.table` and 65 cross-platform/shared tables in `specs/*.table`, `specs/utility/*.table`, `specs/sleuthkit/*.table`, `specs/linwin/*.table`, and `specs/macwin/*.table` from the official `osquery` specifications), including all `extended_schema(WINDOWS, ...)` columns, required `WHERE` clause constraints, and diagnostic SQL patterns.

---

## 1. Critical Platform Rules & Tables NOT Available on Windows

When diagnosing a **Windows** host, **NEVER** query Linux-only, macOS-only (`darwin`), or POSIX-only tables. Always use the Windows-native equivalents listed below:

| Do NOT Query on Windows (Non-Windows Table) | Why It Fails on Windows | Correct Windows Table / Column to Query Instead |
|---|---|---|
| `memory_info`, `memory_map`, `shared_memory`, `virtual_memory_info` | Linux-only / macOS-only | **`system_info`** (`physical_memory` column for total RAM in bytes), **`memory_devices`** (SMBIOS physical RAM DIMMs), **`processes`** (`resident_size`, `wired_size`, `total_size` for per-process RAM usage), and **`process_memory_map`** |
| `physical_memory` *(as a table name)* | **Not a table** (`physical_memory` is a column on `system_info`) | `SELECT hostname, physical_memory FROM system_info;` and `SELECT * FROM memory_devices;` |
| `mounts`, `block_devices` | POSIX-only (`linux,macos`) | **`logical_drives`** (drive letters, free space, total size, filesystem, boot partition), **`disk_info`** (physical drives, partitions, serial, size), and **`physical_disk_performance`** (disk I/O queues, read/write latency, idle %) |
| `disk_encryption` | POSIX-only (`linux,macos`) | **`bitlocker_info`** (`drive_letter`, `protection_status`, `conversion_status`, `percentage_encrypted`, `encryption_method`) |
| `systemd_units`, `launchd`, `launchd_overrides` | Linux-only / macOS-only | **`services`** (Windows Services status, start_type, path, module_path, user_account), **`scheduled_tasks`**, **`startup_items`**, and **`autoexec`** |
| `crontab` | POSIX-only (`linux,macos`) | **`scheduled_tasks`** (`name`, `action`, `path`, `enabled`, `state`, `hidden`, `last_run_time`, `last_run_code`) |
| `iptables`, `alf`, `alf_exceptions`, `pf` | Linux-only / macOS-only | **`windows_firewall_rules`** (`name`, `app_name`, `action`, `enabled`, `direction`, `protocol`, `local_ports`, `remote_ports`, `profile_domain`, `profile_private`, `profile_public`) |
| `syslog_events`, `unified_log`, `asl` | Linux-only / macOS-only | **`windows_eventlog`** (on-demand query of recorded Windows Event Logs; requires `WHERE channel = ...` or `WHERE xpath = ...`), **`windows_events`** (event subscriber), and **`powershell_events`** (event subscriber) |
| `deb_packages`, `rpm_packages`, `apt_sources`, `yum_sources`, `homebrew_packages`, `apps` | Linux-only / macOS-only | **`programs`** (alias `programs_and_features`), **`patches`** (installed KBs/hotfixes), **`windows_update_history`**, **`windows_optional_features`**, and **`chocolatey_packages`** |
| `kernel_modules`, `kernel_extensions`, `system_extensions` | Linux-only / macOS-only | **`drivers`** (in-use Windows device drivers, `image`, `service`, `version`, `signed`, `provider`, `date`) |
| `process_envs`, `process_open_files`, `process_open_pipes` | POSIX-only / Linux-only | **`default_environment`** (system environment variables), **`process_open_handles`** (requires `WHERE pid = ...`), and **`pipes`** (named and anonymous pipes per PID) |
| `load_average`, `cpu_time` | POSIX-only (`linux,macos`) | **`cpu_info`** (Windows-extended `load_percentage` and `availability` columns) and **`processes`** (`user_time`, `system_time`, `percent_processor_time`, `elapsed_time`, `handle_count`) |
| `dns_resolvers` | POSIX-only (`linux,macos`) | **`interface_details`** (`dns_server_search_order`, `dns_domain`, `dns_domain_suffix_search_order`), **`dns_cache`**, and **`dns_lookup_events`** |
| `sudoers`, `shadow`, `last`, `authorized_keys`, `known_hosts` | POSIX-only / Linux-only | **`users`** (includes `uuid` = SID and Windows-extended `type`), **`groups`** (`group_sid`), **`user_groups`**, **`logged_in_users`** (`sid`, `registry_hive`), **`logon_sessions`**, **`security_profile_info`**, and **`ntfs_acl_permissions`** |
| `pci_devices`, `usb_devices`, `smbios_tables`, `acpi_tables`, `hardware_events` | POSIX-only (`linux,macos`) | **`drivers`**, **`disk_info`**, **`video_info`**, **`wmi_bios_info`**, **`chassis_info`**, **`tpm_info`**, **`platform_info`**, and **`system_info`** |
| `signature`, `gatekeeper`, `sip_config`, `xprotect_entries` | macOS-only | **`authenticode`** (requires `WHERE path = ...`), **`windows_security_center`**, **`windows_security_products`**, **`deviceguard_status`** (alias `hvci_status`), and **`secureboot`** |
| `crashes`, `kernel_panics` | macOS-only | **`windows_crashes`** (Minidump crash logs) and **`windows_eventlog`** (`channel = 'System'` with BugCheck/Kernel-Power Event IDs `41`, `1001`, `6008`) |

---

## 2. Required `WHERE` Clause Constraints & Query Rules on Windows

Several `osquery` tables are generator/utility tables that **require** a `WHERE` clause predicate (`required=True`) or strongly require an indexed constraint (`additional=True` / `index=True`) to avoid empty results, errors, or expensive full-system scans.

### 2.1 Tables with Mandatory or Critical `WHERE` Constraints

| Table | Required / Key Columns | Constraint Rules & Windows Usage Notes |
|---|---|---|
| **`file`** | `path` *(required)* OR `directory` *(required)* | Must provide `WHERE path = '...'`, `WHERE directory = '...'`, or `WHERE path LIKE '...'`. On Windows, escape backslashes if needed or use standard SQL strings (e.g., `WHERE directory = 'C:\\Windows\\System32'`). Includes 12 Windows-extended columns (`attributes`, `file_version`, `product_version`, `original_filename`, `shortcut_target_path`, etc.). |
| **`hash`** | `path` *(required)* OR `directory` *(required)* | Must provide `WHERE path = '...'` or `WHERE directory = '...'` (or `JOIN hash USING (path)`). Computes `md5`, `sha1`, `sha256`. |
| **`registry`** | `key` *(additional, optimized)* OR `path` *(indexed, optimized)* | Always filter by `WHERE key = '...'`, `WHERE key LIKE '...'`, `WHERE path = '...'`, or `WHERE path LIKE '...'`. **Important:** `osquery` runs outside the interactive user context and **cannot** resolve `HKEY_CURRENT_USER` (`HKCU`); always query `HKEY_USERS\\<SID>\\...` or `HKEY_USERS\\%\\...` or `HKEY_LOCAL_MACHINE\\...`. Use `%%` at the end of a `LIKE` pattern for recursive subkey traversal. |
| **`windows_eventlog`** | `channel` *(required)* OR `xpath` *(required, hidden)* | Queries recorded Windows Event Logs on demand. You **must** specify `WHERE channel = '...'` (e.g., `'System'`, `'Application'`, `'Security'`, `'Microsoft-Windows-PowerShell/Operational'`) or `WHERE xpath = '...'`. Also supports `additional=True` filters on `eventid`, `pid`, `time_range`, and `timestamp`. |
| **`ntfs_acl_permissions`** | `path` *(required, indexed, optimized)* | Must specify `WHERE path = 'C:\\path\\to\\file_or_dir'`. Returns NTFS ACE entries (`type`, `principal`, `access`, `inherited_from`). |
| **`authenticode`** | `path` *(required, optimized)* | Must specify `WHERE path = 'C:\\path\\to\\binary.exe'` (or `LEFT JOIN authenticode ON processes.path = authenticode.path`). Verify code-signing status (`result`, `subject_name`, `issuer_name`, `serial_number`). |
| **`process_open_handles`** | `pid` *(required, indexed, optimized)* | Must specify `WHERE pid = <pid>`. Enumerates open Windows handles (`type`, `name`, `access`, `value`, `count`) for the target process. |
| **`curl`** | `url` *(required, indexed, optimized)* | Must specify `WHERE url = 'https://...'`. Optionally filter by `user_agent` (`additional=True`). |
| **`curl_certificate`** | `hostname` *(required, optimized)* | Must specify `WHERE hostname = 'example.com'` or `'example.com:443'`. Optionally pass `dump_certificate = 1` or `timeout = <sec>`. |
| **`yara_file`** *(alias: `yara`)* | `path` *(required, indexed)* AND (`sig_group` OR `sigfile` OR `sigrule` OR `sigurl`) | One-off YARA scan of files. Requires both `path` and a signature source in `WHERE`. |
| **`yara_process`** | `pid` *(required, indexed)* AND (`sig_group` OR `sigfile` OR `sigrule` OR `sigurl`) | One-off YARA scan of process memory. Requires both `pid` and a signature source in `WHERE`. |
| **`device_file`** | `device` *(required, indexed)* AND `partition` *(required, indexed)* | Sleuthkit raw partition file listing. Also accepts `path` (`additional=True`). |
| **`device_hash`** | `device` *(required)* AND `partition` *(required)* AND `inode` *(required)* | Sleuthkit raw inode hash calculation. |
| **`device_partitions`** | `device` *(required)* | Sleuthkit partition table enumeration for a raw disk device. |
| **`windows_search`** | `query`, `sort`, `max_results`, `additional_properties` *(all `additional=True`, hidden)* | Queries the Windows Search Index (`SystemIndex`) using Advanced Query Syntax (AQS), e.g., `WHERE query = 'folder:documents' AND max_results = 25`. |
| **`prefetch`** | `path` *(additional, optimized)* | Can be queried directly (`SELECT * FROM prefetch`) or filtered via `WHERE path = 'C:\\Windows\\Prefetch\\...'`. |
| **`carves`** | `path` *(additional)*, `carve` *(additional)* | Query existing carves with `SELECT * FROM carves`, or initiate a new carve with `WHERE path LIKE '...' AND carve = 1`. |

### 2.2 User-Scoped Tables (`user_data=True`)

Tables with `attributes(user_data=True)` (`chrome_extensions`, `chrome_extension_content_scripts`, `firefox_addons`, `vscode_extensions`, `jetbrains_plugins`, `recent_files`, `ssh_configs`, `user_ssh_keys`) require a user context (`uid`). Always join with `users` or filter by `uid`:

```sql
SELECT u.username, r.filename, r.path, r.mtime
FROM users u
CROSS JOIN recent_files r USING (uid)
WHERE u.type != 'special';
```

*(Note: `python_packages` on Windows returns all user-installed Python packages even without a `users` join, though `uid` and `directory` are indexed.)*

### 2.3 Event Subscriber Tables (`event_subscriber=True`) vs. On-Demand Tables

Six tables on Windows are **event subscribers** (`windows_events`, `powershell_events`, `ntfs_journal_events`, `process_etw_events`, `dns_lookup_events`, `yara_events`). They only return rows if the corresponding event publisher/subscriber is enabled in `osquery` flags/configuration (check `SELECT * FROM osquery_events WHERE active = 1;`).
- **For live/interactive diagnostics of Windows Event Logs**, always prefer **`windows_eventlog`** (which reads recorded `.evtx` channels directly on demand) over `windows_events`!

---

## 3. Key Windows Diagnostic Tables & Practical SQL Playbooks

### 3.1 System Identification, CPU & Physical Memory (`system_info`, `os_version`, `uptime`, `cpu_info`, `memory_devices`)
- **Total Physical Memory**: On Windows, `memory_info` does **not** exist. Query `physical_memory` (in bytes) from `system_info`, hardware RAM sticks from `memory_devices`, and per-process memory from `processes`:

```sql
-- Host identity, CPU cores, and total physical memory (in bytes and GiB)
SELECT hostname, computer_name, cpu_brand, cpu_physical_cores, cpu_logical_cores,
       physical_memory, ROUND(physical_memory / 1073741824.0, 2) AS physical_memory_gib,
       hardware_vendor, hardware_model, emulated_cpu_type
FROM system_info;

-- Windows OS build, revision (UBR), architecture, and install timestamp
SELECT name, version, major, minor, build, revision, arch, install_date
FROM os_version;

-- Physical RAM DIMM slots from SMBIOS
SELECT device_locator, bank_locator, size AS size_mb, memory_type,
       configured_clock_speed, manufacturer, part_number
FROM memory_devices;

-- Current CPU clock speed and real-time CPU load percentage (Windows extended columns)
SELECT device_id, model, number_of_cores, logical_processors,
       current_clock_speed, max_clock_speed, availability, load_percentage
FROM cpu_info;
```

### 3.2 Processes, Memory Consumption & Open Handles (`processes`, `process_open_handles`, `process_memory_map`, `pipes`)
- `processes` on Windows includes 7 critical Windows-extended columns: `elevated_token`, `secure_process`, `protection_type`, `virtual_process`, `elapsed_time`, `handle_count`, and `percent_processor_time`.

```sql
-- Top 15 processes by private resident memory (resident_size) on Windows
SELECT pid, name, path, cmdline,
       ROUND(resident_size / 1048576.0, 2) AS resident_mb,
       ROUND(wired_size / 1048576.0, 2) AS wired_mb,
       ROUND(total_size / 1048576.0, 2) AS virtual_mb,
       handle_count, threads, elevated_token, percent_processor_time, elapsed_time
FROM processes
ORDER BY resident_size DESC
LIMIT 15;

-- Top 15 processes by CPU time (user_time + system_time in ms)
SELECT pid, parent, name, path, cmdline,
       (user_time + system_time) AS total_cpu_ms,
       user_time, system_time, percent_processor_time,
       handle_count, elevated_token, on_disk
FROM processes
ORDER BY total_cpu_ms DESC
LIMIT 15;

-- Inspect open handles for a specific process (requires WHERE pid = ...)
SELECT pid, type, name, access, count
FROM process_open_handles
WHERE pid = 1234;
```

### 3.3 Windows Services, Scheduled Tasks & Startup Persistence (`services`, `scheduled_tasks`, `startup_items`, `autoexec`)
```sql
-- Auto-start services that are currently STOPPED (failed or crashed services)
SELECT name, display_name, status, start_type, win32_exit_code, service_exit_code,
       path, module_path, user_account
FROM services
WHERE start_type = 'AUTO_START' AND status != 'RUNNING';

-- Currently running services and their backing executables / DLLs
SELECT pid, name, display_name, service_type, path, module_path, user_account
FROM services
WHERE status = 'RUNNING';

-- Enabled scheduled tasks (including hidden tasks and last run exit codes)
SELECT name, path, action, state, enabled, hidden,
       last_run_time, next_run_time, last_run_code, last_run_message
FROM scheduled_tasks
WHERE enabled = 1;

-- Consolidated startup items and autoexec binaries
SELECT name, path, args, type, source, status, username FROM startup_items;
SELECT name, path, source FROM autoexec;
```

### 3.4 WMI Permanent Event Subscription Persistence (`wmi_cli_event_consumers`, `wmi_script_event_consumers`, `wmi_event_filters`, `wmi_filter_consumer_binding`)
```sql
-- Audit WMI CommandLineEventConsumer bindings and their WQL trigger queries
SELECT wcec.name, wcec.executable_path, wcec.command_line_template,
       wcb.filter, wcb.consumer, wef.query
FROM wmi_cli_event_consumers wcec
LEFT JOIN wmi_filter_consumer_binding wcb ON wcb.consumer = wcec.relative_path
LEFT JOIN wmi_event_filters wef ON wef.relative_path = wcb.filter;

-- Audit WMI ActiveScriptEventConsumer bindings
SELECT wsec.name, wsec.scripting_engine, wsec.script_file_name, wsec.script_text,
       wcb.filter, wef.query
FROM wmi_script_event_consumers wsec
LEFT JOIN wmi_filter_consumer_binding wcb ON wcb.consumer = wsec.relative_path
LEFT JOIN wmi_event_filters wef ON wef.relative_path = wcb.filter;
```

### 3.5 Windows Event Logs, PowerShell & Crash Dumps (`windows_eventlog`, `windows_events`, `powershell_events`, `windows_crashes`)
- Always provide `WHERE channel = '...'` or `WHERE xpath = '...'` when querying `windows_eventlog`.
- Severity levels in Windows Event Logs: `1` = Critical, `2` = Error, `3` = Warning, `4` = Information, `5` = Verbose.

```sql
-- Recent Critical (1) and Error (2) events in the Windows System channel
SELECT datetime, eventid, level, provider_name, pid, data
FROM windows_eventlog
WHERE channel = 'System' AND level IN (1, 2)
ORDER BY datetime DESC
LIMIT 50;

-- Recent Application errors and crashes (Event ID 1000 = Application Error, 1002 = Application Hang)
SELECT datetime, eventid, level, provider_name, data
FROM windows_eventlog
WHERE channel = 'Application' AND eventid IN (1000, 1001, 1002)
ORDER BY datetime DESC
LIMIT 30;

-- Failed logon attempts (Event ID 4625) in the Windows Security channel
SELECT datetime, eventid, provider_name, data
FROM windows_eventlog
WHERE channel = 'Security' AND eventid = 4625
ORDER BY datetime DESC
LIMIT 30;

-- Extracted stack traces and exception codes from Windows Minidump crash logs
SELECT datetime, path, module, pid, exception_code, exception_message,
       exception_address, command_line, crash_path
FROM windows_crashes
ORDER BY datetime DESC;
```

### 3.6 Windows Registry (`registry`)
```sql
-- Query Run / RunOnce registry keys under HKEY_LOCAL_MACHINE
SELECT path, name, type, data, mtime
FROM registry
WHERE key IN (
  'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'
);

-- Query per-user Run keys across all user hives (remember: do not use HKEY_CURRENT_USER)
SELECT path, name, type, data, mtime
FROM registry
WHERE key LIKE 'HKEY_USERS\\%\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
```

### 3.7 Storage, Disks, BitLocker & Performance (`logical_drives`, `disk_info`, `physical_disk_performance`, `bitlocker_info`)
```sql
-- Logical drive space usage and free space percentage
SELECT device_id, description, file_system, boot_partition,
       ROUND(size / 1073741824.0, 2) AS size_gib,
       ROUND(free_space / 1073741824.0, 2) AS free_gib,
       ROUND((free_space * 100.0) / NULLIF(size, 0), 1) AS pct_free
FROM logical_drives;

-- Physical disk hardware inventory
SELECT disk_index, name, manufacturer, hardware_model, serial, type,
       partitions, ROUND(disk_size / 1073741824.0, 2) AS disk_size_gib
FROM disk_info;

-- Real-time physical disk I/O queue length, latency, and busy/idle percentage
SELECT name, current_disk_queue_length,
       avg_disk_read_queue_length, avg_disk_write_queue_length,
       avg_disk_sec_per_read, avg_disk_sec_per_write,
       percent_disk_read_time, percent_disk_write_time,
       percent_disk_time, percent_idle_time
FROM physical_disk_performance;

-- BitLocker drive encryption status
SELECT device_id, drive_letter, conversion_status, protection_status,
       encryption_method, percentage_encrypted, lock_status, protector_types
FROM bitlocker_info;
```

### 3.8 Drivers, Patches, Updates & Installed Software (`drivers`, `patches`, `windows_update_history`, `programs`)
```sql
-- Check for unsigned in-use device drivers
SELECT device_name, image, service, version, provider, manufacturer, date, signed
FROM drivers
WHERE signed = 0;

-- Installed Windows hotfixes/KBs
SELECT hotfix_id, caption, description, installed_by, installed_on
FROM patches
ORDER BY installed_on DESC;

-- Windows Update history (including failed updates where result_code != 'Succeeded')
SELECT date, title, operation, result_code, hresult, update_id
FROM windows_update_history
ORDER BY date DESC
LIMIT 30;

-- Installed MSI/Win32 programs
SELECT name, version, publisher, install_date, install_location
FROM programs
ORDER BY install_date DESC;
```

### 3.9 Windows Security Center, Firewall & Networking (`windows_security_center`, `windows_security_products`, `windows_firewall_rules`, `listening_ports`, `process_open_sockets`)
```sql
-- Overall health of Windows Security Center components
SELECT firewall, autoupdate, antivirus, user_account_control,
       windows_security_center_service, internet_settings
FROM windows_security_center;

-- Registered Antivirus / Firewall products (Client Windows SKUs)
SELECT type, name, state, signatures_up_to_date, remediation_path
FROM windows_security_products;

-- Listening network ports joined with owning process and service
SELECT lp.port, lp.protocol, lp.address, lp.pid,
       p.name AS process_name, p.path AS process_path, s.name AS service_name
FROM listening_ports lp
LEFT JOIN processes p ON lp.pid = p.pid
LEFT JOIN services s ON lp.pid = s.pid AND s.status = 'RUNNING'
ORDER BY lp.port ASC;

-- Active external network connections with process details
SELECT pos.pid, p.name AS process_name, p.path AS process_path,
       pos.local_address, pos.local_port, pos.remote_address, pos.remote_port, pos.state
FROM process_open_sockets pos
LEFT JOIN processes p ON pos.pid = p.pid
WHERE pos.remote_address NOT IN ('', '0.0.0.0', '127.0.0.1', '::', '::1');

-- Enabled inbound Windows Firewall allow rules
SELECT name, app_name, service_name, action, direction, protocol,
       local_ports, remote_addresses, profile_domain, profile_private, profile_public
FROM windows_firewall_rules
WHERE enabled = 1 AND direction = 'In' AND action = 'Allow';
```

---

## 4. Complete Windows Table & Schema Reference (All 118 Tables)

Below is the complete schema specification for every `osquery` table available on Windows, including all `extended_schema(WINDOWS, ...)` columns.

### 1. System, OS, Hardware & Firmware

#### `system_info`
System information for identification. (**Scope**: Cross-platform (`system_info.table`: `linux, macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `hostname` | `TEXT` | - | Network hostname including domain |
| `uuid` | `TEXT` | - | Unique ID provided by the system |
| `cpu_type` | `TEXT` | - | CPU type |
| `cpu_subtype` | `TEXT` | - | CPU subtype |
| `cpu_brand` | `TEXT` | - | CPU brand string, contains vendor and model |
| `cpu_physical_cores` | `INTEGER` | - | Number of physical CPU cores in to the system |
| `cpu_logical_cores` | `INTEGER` | - | Number of logical CPU cores available to the system |
| `cpu_sockets` | `INTEGER` | - | Number of processor sockets in the system |
| `cpu_microcode` | `TEXT` | - | Microcode version |
| `physical_memory` | `BIGINT` | - | Total physical memory in bytes |
| `hardware_vendor` | `TEXT` | - | Hardware vendor |
| `hardware_model` | `TEXT` | - | Hardware model |
| `hardware_version` | `TEXT` | - | Hardware version |
| `hardware_serial` | `TEXT` | - | Device serial number |
| `board_vendor` | `TEXT` | - | Board vendor |
| `board_model` | `TEXT` | - | Board model |
| `board_version` | `TEXT` | - | Board version |
| `board_serial` | `TEXT` | - | Board serial number |
| `computer_name` | `TEXT` | - | Friendly computer name (optional) |
| `local_hostname` | `TEXT` | - | Local hostname (optional) |
| `emulated_cpu_type` | `TEXT` | `WINDOWS-EXT` | Emulated CPU type |

#### `os_version`
A single row containing the operating system name and version. (**Scope**: Cross-platform (`os_version.table`: `linux, macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Distribution or product name |
| `version` | `TEXT` | - | Pretty, suitable for presentation, OS version |
| `major` | `INTEGER` | - | Major release version |
| `minor` | `INTEGER` | - | Minor release version |
| `patch` | `INTEGER` | - | Optional patch release |
| `build` | `TEXT` | - | Optional build-specific or variant string |
| `platform` | `TEXT` | - | OS Platform or ID |
| `platform_like` | `TEXT` | - | Closely related platforms |
| `codename` | `TEXT` | - | OS version codename |
| `arch` | `TEXT` | - | OS Architecture |
| `install_date` | `BIGINT` | `WINDOWS-EXT` | The install date of the OS. |
| `revision` | `INTEGER` | `WINDOWS-EXT` | Update Build Revision, refers to the specific revision number of a Windows update |

#### `uptime`
Track time passed since last boot. Some systems track this as calendar time, some as runtime. (**Scope**: Cross-platform (`uptime.table`: `linux, macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `days` | `INTEGER` | - | Days of uptime |
| `hours` | `INTEGER` | - | Hours of uptime |
| `minutes` | `INTEGER` | - | Minutes of uptime |
| `seconds` | `INTEGER` | - | Seconds of uptime |
| `total_seconds` | `BIGINT` | - | Total uptime seconds |

#### `kernel_info`
Basic active kernel information. (**Scope**: Cross-platform (`kernel_info.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `version` | `TEXT` | - | Kernel version |
| `arguments` | `TEXT` | - | Kernel arguments |
| `path` | `TEXT` | - | Kernel path |
| `device` | `TEXT` | - | Kernel device identifier |

#### `cpu_info`
Retrieve cpu hardware info of the machine. (**Scope**: Cross-platform (`cpu_info.table`: `linux, macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `device_id` | `TEXT` | - | The DeviceID of the CPU. |
| `model` | `TEXT` | - | The model of the CPU. |
| `manufacturer` | `TEXT` | - | The manufacturer of the CPU. |
| `processor_type` | `TEXT` | - | The processor type, such as Central, Math, or Video. |
| `cpu_status` | `INTEGER` | - | The current operating status of the CPU. |
| `number_of_cores` | `TEXT` | - | The number of cores of the CPU. |
| `logical_processors` | `INTEGER` | - | The number of logical processors of the CPU. |
| `address_width` | `TEXT` | - | The width of the CPU address bus. |
| `current_clock_speed` | `INTEGER` | - | The current frequency of the CPU. |
| `max_clock_speed` | `INTEGER` | - | The maximum possible frequency of the CPU. |
| `socket_designation` | `TEXT` | - | The assigned socket on the board for the given CPU. |
| `availability` | `TEXT` | `WINDOWS-EXT` | The availability and status of the CPU. |
| `load_percentage` | `INTEGER` | `WINDOWS-EXT` | The current percentage of utilization of the CPU. |

#### `cpuid`
Useful CPU features from the cpuid ASM call. (**Scope**: Cross-platform (`cpuid.table`: `linux, macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `feature` | `TEXT` | - | Present feature flags |
| `value` | `TEXT` | - | Bit value or string |
| `output_register` | `TEXT` | - | Register used to for feature value |
| `output_bit` | `INTEGER` | - | Bit in register value for feature value |
| `input_eax` | `TEXT` | - | Value of EAX used |

#### `memory_devices`
Physical memory device (type 17) information retrieved from SMBIOS. (**Scope**: Cross-platform (`memory_devices.table`: `linux, macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `handle` | `TEXT` | - | Handle, or instance number, associated with the structure in SMBIOS |
| `array_handle` | `TEXT` | - | The memory array that the device is attached to |
| `form_factor` | `TEXT` | - | Implementation form factor for this memory device |
| `total_width` | `INTEGER` | - | Total width, in bits, of this memory device, including any check or error-correction bits |
| `data_width` | `INTEGER` | - | Data width, in bits, of this memory device |
| `size` | `INTEGER` | - | Size of memory device in Megabyte |
| `set` | `INTEGER` | - | Identifies if memory device is one of a set of devices. A value of 0 indicates no set affiliation. |
| `device_locator` | `TEXT` | - | String number of the string that identifies the physically-labeled socket or board position where the memory device is located |
| `bank_locator` | `TEXT` | - | String number of the string that identifies the physically-labeled bank where the memory device is located |
| `memory_type` | `TEXT` | - | Type of memory used |
| `memory_type_details` | `TEXT` | - | Additional details for memory device |
| `max_speed` | `INTEGER` | - | Max speed of memory device in megatransfers per second (MT/s) |
| `configured_clock_speed` | `INTEGER` | - | Configured speed of memory device in megatransfers per second (MT/s) |
| `manufacturer` | `TEXT` | - | Manufacturer ID string |
| `serial_number` | `TEXT` | - | Serial number of memory device |
| `asset_tag` | `TEXT` | - | Manufacturer specific asset tag of memory device |
| `part_number` | `TEXT` | - | Manufacturer specific serial number of memory device |
| `min_voltage` | `INTEGER` | - | Minimum operating voltage of device in millivolts |
| `max_voltage` | `INTEGER` | - | Maximum operating voltage of device in millivolts |
| `configured_voltage` | `INTEGER` | - | Configured operating voltage of device in millivolts |

#### `platform_info`
Information about EFI/UEFI/ROM and platform/boot. (**Scope**: Cross-platform (`platform_info.table`: `linux, macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `vendor` | `TEXT` | - | Platform code vendor |
| `version` | `TEXT` | - | Platform code version |
| `date` | `TEXT` | - | Self-reported platform code update date |
| `revision` | `TEXT` | - | BIOS major and minor revision |
| `extra` | `TEXT` | - | Platform-specific additional information |
| `firmware_type` | `TEXT` | - | The type of firmware (uefi, bios, iboot, openfirmware, unknown). |

#### `wmi_bios_info`
Lists important information from the system bios. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Name of the Bios setting |
| `value` | `TEXT` | - | Value of the Bios setting |

#### `chassis_info`
Display information pertaining to the chassis and its security status. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `audible_alarm` | `TEXT` | - | If TRUE, the frame is equipped with an audible alarm. |
| `breach_description` | `TEXT` | - | If provided, gives a more detailed description of a detected security breach. |
| `chassis_types` | `TEXT` | - | A comma-separated list of chassis types, such as Desktop or Laptop. |
| `description` | `TEXT` | - | An extended description of the chassis if available. |
| `lock` | `TEXT` | - | If TRUE, the frame is equipped with a lock. |
| `manufacturer` | `TEXT` | - | The manufacturer of the chassis. |
| `model` | `TEXT` | - | The model of the chassis. |
| `security_breach` | `TEXT` | - | The physical status of the chassis such as Breach Successful, Breach Attempted, etc. |
| `serial` | `TEXT` | - | The serial number of the chassis. |
| `smbios_tag` | `TEXT` | - | The assigned asset tag number of the chassis. |
| `sku` | `TEXT` | - | The Stock Keeping Unit number if available. |
| `status` | `TEXT` | - | If available, gives various operational or nonoperational statuses such as OK, Degraded, and Pred Fail. |
| `visible_alarm` | `TEXT` | - | If TRUE, the frame is equipped with a visual alarm. |

#### `video_info`
Retrieve video card information of the machine. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `color_depth` | `INTEGER` | - | The amount of bits per pixel to represent color. |
| `driver` | `TEXT` | - | The driver of the device. |
| `driver_date` | `BIGINT` | - | The date listed on the installed driver. |
| `driver_version` | `TEXT` | - | The version of the installed driver. |
| `manufacturer` | `TEXT` | - | The manufacturer of the gpu. |
| `model` | `TEXT` | - | The model of the gpu. |
| `series` | `TEXT` | - | The series of the gpu. |
| `video_mode` | `TEXT` | - | The current resolution of the display. |

#### `battery`
Provides information about the internal battery of a laptop. Note: On Windows, columns with Ah or mAh units assume that the battery is 12V. (**Scope**: Cross-platform (`macwin/battery.table`: `macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `manufacturer` | `TEXT` | - | The battery manufacturer's name |
| `model` | `TEXT` | - | The battery's model number |
| `serial_number` | `TEXT` | - | The battery's serial number |
| `cycle_count` | `INTEGER` | - | The number of charge/discharge cycles |
| `state` | `TEXT` | - | One of the following: "AC Power" indicates the battery is connected to an external power source, "Battery Power" indicates that the battery is drawing internal power, "Off Line" indicates the battery is off-line or no longer connected |
| `charging` | `INTEGER` | - | 1 if the battery is currently being charged by a power source. 0 otherwise |
| `charged` | `INTEGER` | - | 1 if the battery is currently completely charged. 0 otherwise |
| `designed_capacity` | `INTEGER` | - | The battery's designed capacity in mAh |
| `max_capacity` | `INTEGER` | - | The battery's actual capacity when it is fully charged in mAh |
| `current_capacity` | `INTEGER` | - | The battery's current capacity (level of charge) in mAh |
| `percent_remaining` | `INTEGER` | - | The percentage of battery remaining before it is drained |
| `amperage` | `INTEGER` | - | The current amperage in/out of the battery in mA (positive means charging, negative means discharging) |
| `voltage` | `INTEGER` | - | The battery's current voltage in mV |
| `minutes_until_empty` | `INTEGER` | - | The number of minutes until the battery is fully depleted. This value is -1 if this time is still being calculated |
| `minutes_to_full_charge` | `INTEGER` | - | The number of minutes until the battery is fully charged. This value is -1 if this time is still being calculated. On Windows this is calculated from the charge rate and capacity and may not agree with the number reported in "Power & Battery" |
| `chemistry` | `TEXT` | `WINDOWS-EXT` | The battery chemistry type (eg. LiP). Some possible values are documented in https://learn.microsoft.com/en-us/windows/win32/power/battery-information-str. |

#### `intel_me_info`
Intel ME/CSE Info. (**Scope**: Cross-platform (`linwin/intel_me_info.table`: `linux, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `version` | `TEXT` | - | Intel ME version |

#### `kva_speculative_info`
Display kernel virtual address and speculative execution information for the system. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `kva_shadow_enabled` | `INTEGER` | - | Kernel Virtual Address shadowing is enabled. |
| `kva_shadow_user_global` | `INTEGER` | - | User pages are marked as global. |
| `kva_shadow_pcid` | `INTEGER` | - | Kernel VA PCID flushing optimization is enabled. |
| `kva_shadow_inv_pcid` | `INTEGER` | - | Kernel VA INVPCID is enabled. |
| `bp_mitigations` | `INTEGER` | - | Branch Prediction mitigations are enabled. |
| `bp_system_pol_disabled` | `INTEGER` | - | Branch Predictions are disabled via system policy. |
| `bp_microcode_disabled` | `INTEGER` | - | Branch Predictions are disabled due to lack of microcode update. |
| `cpu_spec_ctrl_supported` | `INTEGER` | - | SPEC_CTRL MSR supported by CPU Microcode. |
| `ibrs_support_enabled` | `INTEGER` | - | Windows uses IBRS. |
| `stibp_support_enabled` | `INTEGER` | - | Windows uses STIBP. |
| `cpu_pred_cmd_supported` | `INTEGER` | - | PRED_CMD MSR supported by CPU Microcode. |

#### `default_environment`
Default environment variables and values. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `variable` | `TEXT` | - | Name of the environment variable |
| `value` | `TEXT` | - | Value of the environment variable |
| `expand` | `INTEGER` | - | 1 if the variable needs expanding, 0 otherwise |

### 2. Processes, Services, Scheduled Tasks & Persistence

#### `processes`
All running processes on the host system. (**Scope**: Cross-platform (`processes.table`: `linux, macos, windows`) | **Indexed**: `pid` | **Attributes**: `cacheable=True`, `strongly_typed_rows=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `pid` | `BIGINT` | `INDEX`, `OPTIMIZED` | Process (or thread) ID |
| `name` | `TEXT` | - | The process path or shorthand argv[0] |
| `path` | `TEXT` | - | Path to executed binary |
| `cmdline` | `TEXT` | - | Complete argv |
| `state` | `TEXT` | - | Process state |
| `cwd` | `TEXT` | - | Process current working directory |
| `root` | `TEXT` | - | Process virtual root directory |
| `uid` | `BIGINT` | - | Unsigned user ID |
| `gid` | `BIGINT` | - | Unsigned group ID |
| `euid` | `BIGINT` | - | Unsigned effective user ID |
| `egid` | `BIGINT` | - | Unsigned effective group ID |
| `suid` | `BIGINT` | - | Unsigned saved user ID |
| `sgid` | `BIGINT` | - | Unsigned saved group ID |
| `on_disk` | `INTEGER` | - | The process path exists yes=1, no=0, unknown=-1 |
| `wired_size` | `BIGINT` | - | Bytes of unpageable memory used by process |
| `resident_size` | `BIGINT` | - | Bytes of private memory used by process |
| `total_size` | `BIGINT` | - | Total virtual memory size (Linux, Windows) or 'footprint' (macOS) |
| `user_time` | `BIGINT` | - | CPU time in milliseconds spent in user space |
| `system_time` | `BIGINT` | - | CPU time in milliseconds spent in kernel space |
| `disk_bytes_read` | `BIGINT` | - | Bytes read from disk |
| `disk_bytes_written` | `BIGINT` | - | Bytes written to disk |
| `start_time` | `BIGINT` | - | Process start time in seconds since Epoch, in case of error -1 |
| `parent` | `BIGINT` | - | Process parent's PID |
| `pgroup` | `BIGINT` | - | Process group |
| `threads` | `INTEGER` | - | Number of threads used by process |
| `nice` | `INTEGER` | - | Process nice level (-20 to 20, default 0) |
| `elevated_token` | `INTEGER` | `WINDOWS-EXT` | Process uses elevated token yes=1, no=0 |
| `secure_process` | `INTEGER` | `WINDOWS-EXT` | Process is secure (IUM) yes=1, no=0 |
| `protection_type` | `TEXT` | `WINDOWS-EXT` | The protection type of the process |
| `virtual_process` | `INTEGER` | `WINDOWS-EXT` | Process is virtual (e.g. System, Registry, vmmem) yes=1, no=0 |
| `elapsed_time` | `BIGINT` | `WINDOWS-EXT` | Elapsed time in seconds this process has been running. |
| `handle_count` | `BIGINT` | `WINDOWS-EXT` | Total number of handles that the process has open. This number is the sum of the handles currently opened by each thread in the process. |
| `percent_processor_time` | `BIGINT` | `WINDOWS-EXT` | Returns elapsed time that all of the threads of this process used the processor to execute instructions in 100 nanoseconds ticks. |

#### `process_memory_map`
Process memory mapped files and pseudo device/regions. (**Scope**: Cross-platform (`process_memory_map.table`: `linux, macos, windows`) | **Indexed**: `pid`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `pid` | `INTEGER` | `INDEX`, `OPTIMIZED` | Process (or thread) ID |
| `start` | `TEXT` | - | Virtual start address (hex) |
| `end` | `TEXT` | - | Virtual end address (hex) |
| `permissions` | `TEXT` | - | r=read, w=write, x=execute, p=private (cow) |
| `offset` | `BIGINT` | - | Offset into mapped path |
| `device` | `TEXT` | - | MA:MI Major/minor device ID |
| `inode` | `INTEGER` | - | Mapped path inode, 0 means uninitialized (BSS) |
| `path` | `TEXT` | - | Path to mapped file or mapped type |
| `pseudo` | `INTEGER` | - | 1 If path is a pseudo path, else 0 |

#### `process_open_handles`
Enumerate open handles for a specified process. (**Scope**: Windows-only (`specs/windows/`) | **Required `WHERE`**: `pid` | **Indexed**: `pid` | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `pid` | `BIGINT` | `REQUIRED`, `INDEX`, `OPTIMIZED` | The process identifier that owns the handle. |
| `value` | `BIGINT` | - | The handle value |
| `type` | `TEXT` | - | The type of object referenced by the handle. |
| `access` | `TEXT` | - | The access permissions of the object referenced by the handle. |
| `name` | `TEXT` | - | The value of the object referenced by the handle. |
| `attributes` | `TEXT` | - | Object handle attributes. |
| `count` | `BIGINT` | - | Handle Count. |
| `raw_pointer_count` | `BIGINT` | - | Raw Pointer/Reference Count. Meaning varies, consult Windows docs. |
| `error_stage` | `TEXT` | - | Error Stage. |
| `error_code` | `BIGINT` | - | Error Code. |

#### `process_etw_events`
Windows process execution events. (**Scope**: Windows-only (`specs/windows/`) | **Additional filters**: `time` | **Attributes**: `event_subscriber=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `type` | `TEXT` | - | Event Type (ProcessStart, ProcessStop) |
| `pid` | `BIGINT` | - | Process ID |
| `ppid` | `BIGINT` | - | Parent Process ID |
| `session_id` | `INTEGER` | - | Session ID |
| `flags` | `INTEGER` | - | Process Flags |
| `exit_code` | `INTEGER` | - | Exit Code - Present only on ProcessStop events |
| `path` | `TEXT` | - | Path of executed binary |
| `cmdline` | `TEXT` | - | Command Line |
| `username` | `TEXT` | - | User rights - primary token username |
| `token_elevation_type` | `TEXT` | - | Primary token elevation type - Present only on ProcessStart events |
| `token_elevation_status` | `INTEGER` | - | Primary token elevation status - Present only on ProcessStart events |
| `mandatory_label` | `TEXT` | - | Primary token mandatory label sid - Present only on ProcessStart events |
| `datetime` | `DATETIME` | - | Event timestamp in DATETIME format |
| `time_windows` | `BIGINT` | `HIDDEN` | Event timestamp in Windows format |
| `time` | `BIGINT` | `ADDITIONAL`, `HIDDEN` | Event timestamp in Unix format |
| `eid` | `INTEGER` | `HIDDEN` | Event ID |
| `header_pid` | `BIGINT` | `HIDDEN` | Process ID of the process reporting the event |
| `process_sequence_number` | `BIGINT` | `HIDDEN` | Process Sequence Number - Present only on ProcessStart events |
| `parent_process_sequence_number` | `BIGINT` | `HIDDEN` | Parent Process Sequence Number - Present only on ProcessStart events |

#### `services`
Lists all installed Windows services and their relevant data. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Service name |
| `service_type` | `TEXT` | - | Service Type: OWN_PROCESS, SHARE_PROCESS and maybe Interactive (can interact with the desktop) |
| `display_name` | `TEXT` | - | Service Display name |
| `status` | `TEXT` | - | Service Current status: STOPPED, START_PENDING, STOP_PENDING, RUNNING, CONTINUE_PENDING, PAUSE_PENDING, PAUSED |
| `pid` | `INTEGER` | - | the Process ID of the service |
| `start_type` | `TEXT` | - | Service start type: BOOT_START, SYSTEM_START, AUTO_START, DEMAND_START, DISABLED |
| `win32_exit_code` | `INTEGER` | - | The error code that the service uses to report an error that occurs when it is starting or stopping |
| `service_exit_code` | `INTEGER` | - | The service-specific error code that the service returns when an error occurs while the service is starting or stopping |
| `path` | `TEXT` | - | Path to Service Executable |
| `module_path` | `TEXT` | - | Path to ServiceDll |
| `description` | `TEXT` | - | Service Description |
| `user_account` | `TEXT` | - | The name of the account that the service process will be logged on as when it runs. This name can be of the form Domain\UserName. If the account belongs to the built-in domain, the name can be of the form .\UserName. |

#### `scheduled_tasks`
Lists all of the tasks in the Windows task scheduler. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Name of the scheduled task |
| `action` | `TEXT` | - | Actions executed by the scheduled task |
| `path` | `TEXT` | - | Path to the executable to be run |
| `enabled` | `INTEGER` | - | Whether or not the scheduled task is enabled |
| `state` | `TEXT` | - | State of the scheduled task |
| `hidden` | `INTEGER` | - | Whether or not the task is visible in the UI |
| `last_run_time` | `BIGINT` | - | Timestamp the task last ran |
| `next_run_time` | `BIGINT` | - | Timestamp the task is scheduled to run next |
| `last_run_message` | `TEXT` | - | Exit status message of the last task run |
| `last_run_code` | `TEXT` | - | Exit status code of the last task run |

#### `startup_items`
Applications and binaries set as startup items. (**Scope**: Cross-platform (`startup_items.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Name of startup item |
| `path` | `TEXT` | - | Path of startup item |
| `args` | `TEXT` | - | Arguments provided to startup executable |
| `type` | `TEXT` | - | Type of startup item. On macOS this can be app, agent (LaunchAgent), daemon (LaunchDaemon), login item, or user item. |
| `source` | `TEXT` | - | Directory containing startup item (on macOS, the subsystem providing it) |
| `status` | `TEXT` | - | Startup status. On Linux: enabled or disabled. On macOS: Combination of enabled, allowed, notified, and hidden. |
| `username` | `TEXT` | - | The user associated with the startup item |

#### `autoexec`
Aggregate of executables that will automatically execute on the target machine. This is an amalgamation of other tables like services, scheduled_tasks, startup_items and more. (**Scope**: Windows-only (`specs/windows/`) | **Indexed**: `path`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `path` | `TEXT` | `INDEX` | Path to the executable |
| `name` | `TEXT` | - | Name of the program |
| `source` | `TEXT` | - | Source table of the autoexec item |

#### `pipes`
Named and Anonymous pipes. (**Scope**: Windows-only (`specs/windows/`) | **Indexed**: `pid`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `pid` | `BIGINT` | `INDEX` | Process ID of the process to which the pipe belongs |
| `name` | `TEXT` | - | Name of the pipe |
| `instances` | `INTEGER` | - | Number of instances of the named pipe |
| `max_instances` | `INTEGER` | - | The maximum number of instances creatable for this pipe |
| `flags` | `TEXT` | - | The flags indicating whether this pipe connection is a server or client end, and if the pipe for sending messages or bytes |

#### `winbaseobj`
Lists named Windows objects in the default object directories, across all terminal services sessions. Example Windows object types include Mutexes, Events, Jobs and Semaphors. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `session_id` | `INTEGER` | - | Terminal Services Session Id |
| `object_name` | `TEXT` | - | Object Name |
| `object_type` | `TEXT` | - | Object Type |

#### `wmi_cli_event_consumers`
WMI CommandLineEventConsumer, which can be used for persistence on Windows. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `namespace` | `TEXT` | - | The WMI namespace where the consumer was found. |
| `name` | `TEXT` | - | Unique name of a consumer. |
| `command_line_template` | `TEXT` | - | Standard string template that specifies the process to be started. This property can be NULL, and the ExecutablePath property is used as the command line. |
| `executable_path` | `TEXT` | - | Module to execute. The string can specify the full path and file name of the module to execute, or it can specify a partial name. |
| `class` | `TEXT` | - | The name of the class. |
| `relative_path` | `TEXT` | - | Relative path to the class or instance. |

#### `wmi_script_event_consumers`
WMI ActiveScriptEventConsumer, which can be used for persistence on Windows. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `namespace` | `TEXT` | - | The WMI namespace where the consumer was found. |
| `name` | `TEXT` | - | Unique identifier for the event consumer. |
| `scripting_engine` | `TEXT` | - | Name of the scripting engine to use, for example, 'VBScript'. This property cannot be NULL. |
| `script_file_name` | `TEXT` | - | Name of the file from which the script text is read, intended as an alternative to specifying the text of the script in the ScriptText property. |
| `script_text` | `TEXT` | - | Text of the script that is expressed in a language known to the scripting engine. This property must be NULL if the ScriptFileName property is not NULL. |
| `class` | `TEXT` | - | The name of the class. |
| `relative_path` | `TEXT` | - | Relative path to the class or instance. |

#### `wmi_event_filters`
Lists WMI event filters. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `namespace` | `TEXT` | - | The WMI namespace where the filter was found. |
| `name` | `TEXT` | - | Unique identifier of an event filter. |
| `query` | `TEXT` | - | Windows Management Instrumentation Query Language (WQL) event query that specifies the set of events for consumer notification, and the specific conditions for notification. |
| `query_language` | `TEXT` | - | Query language that the query is written in. |
| `class` | `TEXT` | - | The name of the class. |
| `relative_path` | `TEXT` | - | Relative path to the class or instance. |

#### `wmi_filter_consumer_binding`
Lists the relationship between event consumers and filters. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `namespace` | `TEXT` | - | The WMI namespace where the binding was found. |
| `consumer` | `TEXT` | - | Reference to an instance of __EventConsumer that represents the object path to a logical consumer, the recipient of an event. |
| `filter` | `TEXT` | - | Reference to an instance of __EventFilter that represents the object path to an event filter which is a query that specifies the type of event to be received. |
| `class` | `TEXT` | - | The name of the class. |
| `relative_path` | `TEXT` | - | Relative path to the class or instance. |

### 3. Windows Registry

#### `registry`
All of the Windows registry hives. (**Scope**: Windows-only (`specs/windows/`) | **Additional filters**: `key` | **Indexed**: `path`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `key` | `TEXT` | `ADDITIONAL`, `OPTIMIZED` | Name of the key to search for |
| `path` | `TEXT` | `INDEX`, `OPTIMIZED` | Full path to the value |
| `name` | `TEXT` | - | Name of the registry value entry |
| `type` | `TEXT` | - | Type of the registry value, or 'subkey' if item is a subkey |
| `data` | `TEXT` | - | Data content of registry value |
| `mtime` | `BIGINT` | - | timestamp of the most recent registry write |

### 4. Windows Event Logs, PowerShell & Crash Diagnostics

#### `windows_eventlog`
Table for querying all recorded Windows event logs. (**Scope**: Windows-only (`specs/windows/`) | **Required `WHERE`**: `channel, xpath` | **Additional filters**: `eventid, pid, time_range, timestamp`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `channel` | `TEXT` | `REQUIRED` | Source or channel of the event |
| `datetime` | `TEXT` | - | System time at which the event occurred |
| `task` | `INTEGER` | - | Task value associated with the event |
| `level` | `INTEGER` | - | Severity level associated with the event |
| `provider_name` | `TEXT` | - | Provider name of the event |
| `provider_guid` | `TEXT` | - | Provider guid of the event |
| `computer_name` | `TEXT` | - | Hostname of system where event was generated |
| `eventid` | `INTEGER` | `ADDITIONAL` | Event ID of the event |
| `keywords` | `TEXT` | - | A bitmask of the keywords defined in the event |
| `data` | `TEXT` | - | Data associated with the event |
| `pid` | `INTEGER` | `ADDITIONAL` | Process ID which emitted the event record |
| `tid` | `INTEGER` | - | Thread ID which emitted the event record |
| `time_range` | `TEXT` | `ADDITIONAL`, `HIDDEN` | System time to selectively filter the events |
| `timestamp` | `TEXT` | `ADDITIONAL`, `HIDDEN` | Timestamp to selectively filter the events |
| `xpath` | `TEXT` | `REQUIRED`, `HIDDEN` | The custom query to filter events |

#### `windows_events`
Windows Event logs. (**Scope**: Windows-only (`specs/windows/`) | **Additional filters**: `time` | **Attributes**: `event_subscriber=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `time` | `BIGINT` | `ADDITIONAL` | Timestamp the event was received |
| `datetime` | `TEXT` | - | System time at which the event occurred |
| `source` | `TEXT` | - | Source or channel of the event |
| `provider_name` | `TEXT` | - | Provider name of the event |
| `provider_guid` | `TEXT` | - | Provider guid of the event |
| `computer_name` | `TEXT` | - | Hostname of system where event was generated |
| `eventid` | `INTEGER` | - | Event ID of the event |
| `task` | `INTEGER` | - | Task value associated with the event |
| `level` | `INTEGER` | - | The severity level associated with the event |
| `keywords` | `TEXT` | - | A bitmask of the keywords defined in the event |
| `data` | `TEXT` | - | Data associated with the event |
| `eid` | `TEXT` | `HIDDEN` | Event ID |

#### `powershell_events`
Powershell script blocks reconstructed to their full script content, this table requires script block logging to be enabled. (**Scope**: Windows-only (`specs/windows/`) | **Additional filters**: `time` | **Attributes**: `event_subscriber=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `time` | `BIGINT` | `ADDITIONAL` | Timestamp the event was received by the osquery event publisher |
| `datetime` | `TEXT` | - | System time at which the Powershell script event occurred |
| `script_block_id` | `TEXT` | - | The unique GUID of the powershell script to which this block belongs |
| `script_block_count` | `INTEGER` | - | The total number of script blocks for this script |
| `script_text` | `TEXT` | - | The text content of the Powershell script |
| `script_name` | `TEXT` | - | The name of the Powershell script |
| `script_path` | `TEXT` | - | The path for the Powershell script |
| `cosine_similarity` | `DOUBLE` | - | How similar the Powershell script is to a provided 'normal' character frequency |

#### `windows_crashes`
Extracted information from Windows crash logs (Minidumps). (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `datetime` | `TEXT` | - | Timestamp (log format) of the crash |
| `module` | `TEXT` | - | Path of the crashed module within the process |
| `path` | `TEXT` | - | Path of the executable file for the crashed process |
| `pid` | `BIGINT` | - | Process ID of the crashed process |
| `tid` | `BIGINT` | - | Thread ID of the crashed thread |
| `version` | `TEXT` | - | File version info of the crashed process |
| `process_uptime` | `BIGINT` | - | Uptime of the process in seconds |
| `stack_trace` | `TEXT` | - | Multiple stack frames from the stack trace |
| `exception_code` | `TEXT` | - | The Windows exception code |
| `exception_message` | `TEXT` | - | The NTSTATUS error message associated with the exception code |
| `exception_address` | `TEXT` | - | Address (in hex) where the exception occurred |
| `registers` | `TEXT` | - | The values of the system registers |
| `command_line` | `TEXT` | - | Command-line string passed to the crashed process |
| `current_directory` | `TEXT` | - | Current working directory of the crashed process |
| `username` | `TEXT` | - | Username of the user who ran the crashed process |
| `machine_name` | `TEXT` | - | Name of the machine where the crash happened |
| `major_version` | `INTEGER` | - | Windows major version of the machine |
| `minor_version` | `INTEGER` | - | Windows minor version of the machine |
| `build_number` | `INTEGER` | - | Windows build number of the crashing machine |
| `type` | `TEXT` | - | Type of crash log |
| `crash_path` | `TEXT` | - | Path of the log file |

### 5. Storage, Disks, Filesystem & Forensics

#### `logical_drives`
Details for logical drives on the system. A logical drive generally represents a single partition. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `device_id` | `TEXT` | - | The drive id, usually the drive name, e.g., 'C:'. |
| `type` | `TEXT` | - | Deprecated (always 'Unknown'). |
| `description` | `TEXT` | - | The canonical description of the drive, e.g. 'Logical Fixed Disk', 'CD-ROM Disk'. |
| `free_space` | `BIGINT` | - | The amount of free space, in bytes, of the drive (-1 on failure). |
| `size` | `BIGINT` | - | The total amount of space, in bytes, of the drive (-1 on failure). |
| `file_system` | `TEXT` | - | The file system of the drive. |
| `boot_partition` | `INTEGER` | - | True if Windows booted from this drive. |

#### `disk_info`
Retrieve basic information about the physical disks of a system. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `partitions` | `INTEGER` | - | Number of detected partitions on disk. |
| `disk_index` | `INTEGER` | - | Physical drive number of the disk. |
| `type` | `TEXT` | - | The interface type of the disk. |
| `id` | `TEXT` | - | The unique identifier of the drive on the system. |
| `pnp_device_id` | `TEXT` | - | The unique identifier of the drive on the system. |
| `disk_size` | `BIGINT` | - | Size of the disk. |
| `manufacturer` | `TEXT` | - | The manufacturer of the disk. |
| `hardware_model` | `TEXT` | - | Hard drive model. |
| `name` | `TEXT` | - | The label of the disk object. |
| `serial` | `TEXT` | - | The serial number of the disk. |
| `description` | `TEXT` | - | The OS's description of the disk. |

#### `physical_disk_performance`
Provides raw data from performance counters that monitor hard or fixed disk drives on the system. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Name of the physical disk |
| `avg_disk_bytes_per_read` | `BIGINT` | - | Average number of bytes transferred from the disk during read operations |
| `avg_disk_bytes_per_write` | `BIGINT` | - | Average number of bytes transferred to the disk during write operations |
| `avg_disk_read_queue_length` | `BIGINT` | - | Average number of read requests that were queued for the selected disk during the sample interval |
| `avg_disk_write_queue_length` | `BIGINT` | - | Average number of write requests that were queued for the selected disk during the sample interval |
| `avg_disk_sec_per_read` | `INTEGER` | - | Average time, in seconds, of a read operation of data from the disk |
| `avg_disk_sec_per_write` | `INTEGER` | - | Average time, in seconds, of a write operation of data to the disk |
| `current_disk_queue_length` | `INTEGER` | - | Number of requests outstanding on the disk at the time the performance data is collected |
| `percent_disk_read_time` | `BIGINT` | - | Percentage of elapsed time that the selected disk drive is busy servicing read requests |
| `percent_disk_write_time` | `BIGINT` | - | Percentage of elapsed time that the selected disk drive is busy servicing write requests |
| `percent_disk_time` | `BIGINT` | - | Percentage of elapsed time that the selected disk drive is busy servicing read or write requests |
| `percent_idle_time` | `BIGINT` | - | Percentage of time during the sample interval that the disk was idle |

#### `file`
Interactive filesystem attributes and metadata. (**Scope**: Cross-platform (`utility/file.table`: `linux, macos, windows`) | **Required `WHERE`**: `path, directory` | **Indexed**: `path` | **Attributes**: `utility=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `path` | `TEXT` | `REQUIRED`, `INDEX`, `OPTIMIZED` | Absolute file path |
| `directory` | `TEXT` | `REQUIRED`, `OPTIMIZED` | Directory of file(s) |
| `filename` | `TEXT` | - | Name portion of file path |
| `inode` | `BIGINT` | - | Filesystem inode number |
| `uid` | `BIGINT` | - | Owning user ID |
| `gid` | `BIGINT` | - | Owning group ID |
| `mode` | `TEXT` | - | Permission bits |
| `device` | `BIGINT` | - | Device ID (optional) |
| `size` | `BIGINT` | - | Size of file in bytes |
| `block_size` | `INTEGER` | - | Block size of filesystem |
| `atime` | `BIGINT` | - | Last access time |
| `mtime` | `BIGINT` | - | Last modification time |
| `ctime` | `BIGINT` | - | Last status change time |
| `btime` | `BIGINT` | - | (B)irth or (cr)eate time |
| `hard_links` | `INTEGER` | - | Number of hard links |
| `symlink` | `INTEGER` | - | 1 if the path is a symlink, otherwise 0 |
| `type` | `TEXT` | - | File status |
| `symlink_target_path` | `TEXT` | - | Full path of the symlink target if any |
| `attributes` | `TEXT` | `WINDOWS-EXT` | File attrib string. See: https://ss64.com/nt/attrib.html |
| `volume_serial` | `TEXT` | `WINDOWS-EXT` | Volume serial number |
| `file_id` | `TEXT` | `WINDOWS-EXT` | file ID |
| `file_version` | `TEXT` | `WINDOWS-EXT` | File version |
| `product_version` | `TEXT` | `WINDOWS-EXT` | File product version |
| `original_filename` | `TEXT` | `WINDOWS-EXT` | (Executable files only) Original filename |
| `shortcut_target_path` | `TEXT` | `WINDOWS-EXT` | Full path to the file the shortcut points to |
| `shortcut_target_type` | `TEXT` | `WINDOWS-EXT` | Display name for the target type |
| `shortcut_target_location` | `TEXT` | `WINDOWS-EXT` | Folder name where the shortcut target resides |
| `shortcut_start_in` | `TEXT` | `WINDOWS-EXT` | Full path to the working directory to use when executing the shortcut target |
| `shortcut_run` | `TEXT` | `WINDOWS-EXT` | Window mode the target of the shortcut should be run in |
| `shortcut_comment` | `TEXT` | `WINDOWS-EXT` | Comment on the shortcut |

#### `hash`
Filesystem hash data. (**Scope**: Cross-platform (`hash.table`: `linux, macos, windows`) | **Required `WHERE`**: `path, directory` | **Indexed**: `path`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `path` | `TEXT` | `REQUIRED`, `INDEX`, `OPTIMIZED` | Must provide a path or directory |
| `directory` | `TEXT` | `REQUIRED`, `OPTIMIZED` | Must provide a path or directory |
| `md5` | `TEXT` | - | MD5 hash of provided filesystem data |
| `sha1` | `TEXT` | - | SHA1 hash of provided filesystem data |
| `sha256` | `TEXT` | - | SHA256 hash of provided filesystem data |

#### `ntfs_acl_permissions`
Retrieve NTFS ACL permission information for files and directories. (**Scope**: Windows-only (`specs/windows/`) | **Required `WHERE`**: `path` | **Indexed**: `path`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `path` | `TEXT` | `REQUIRED`, `INDEX`, `OPTIMIZED` | Path to the file or directory. |
| `type` | `TEXT` | - | Type of access mode for the access control entry. |
| `principal` | `TEXT` | - | User or group to which the ACE applies. |
| `access` | `TEXT` | - | Specific permissions that indicate the rights described by the ACE. |
| `inherited_from` | `TEXT` | - | The inheritance policy of the ACE. |

#### `ntfs_journal_events`
Track time/action changes to files specified in configuration data. (**Scope**: Windows-only (`specs/windows/`) | **Additional filters**: `time` | **Attributes**: `event_subscriber=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `action` | `TEXT` | - | Change action (Write, Delete, etc) |
| `category` | `TEXT` | - | The category that the event originated from |
| `old_path` | `TEXT` | - | Old path (renames only) |
| `path` | `TEXT` | - | Path |
| `record_timestamp` | `TEXT` | - | Journal record timestamp |
| `record_usn` | `TEXT` | - | The update sequence number that identifies the journal record |
| `node_ref_number` | `TEXT` | - | The ordinal that associates a journal record with a filename |
| `parent_ref_number` | `TEXT` | - | The ordinal that associates a journal record with a filename's parent directory |
| `drive_letter` | `TEXT` | - | The drive letter identifying the source journal |
| `file_attributes` | `TEXT` | - | File attributes |
| `partial` | `BIGINT` | - | Set to 1 if either path or old_path only contains the file or folder name |
| `time` | `BIGINT` | `ADDITIONAL` | Time of file event |
| `eid` | `TEXT` | `HIDDEN` | Event ID |

#### `windows_search`
Run searches against the Windows system index database using Advanced Query Syntax. (**Scope**: Windows-only (`specs/windows/`) | **Additional filters**: `query, sort, max_results, additional_properties`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | The name of the item |
| `path` | `TEXT` | - | The full path of the item. |
| `size` | `BIGINT` | - | The item size in bytes. |
| `date_created` | `INTEGER` | - | The unix timestamp of when the item was created. |
| `date_modified` | `INTEGER` | - | The unix timestamp of when the item was last modified |
| `owner` | `TEXT` | - | The owner of the item |
| `type` | `TEXT` | - | The item type |
| `properties` | `TEXT` | - | Additional property values JSON |
| `query` | `TEXT` | `ADDITIONAL`, `HIDDEN` | Windows search query |
| `sort` | `TEXT` | `ADDITIONAL`, `HIDDEN` | Sort for windows api |
| `max_results` | `INTEGER` | `ADDITIONAL`, `HIDDEN` | Maximum number of results returned by windows api, set to -1 for unlimited |
| `additional_properties` | `TEXT` | `ADDITIONAL`, `HIDDEN` | Comma separated list of columns to include in properties JSON |

#### `carves`
List the set of completed and in-progress carves. If carve=1 then the query is treated as a new carve request. (**Scope**: Cross-platform (`carves.table`: `linux, macos, windows`) | **Additional filters**: `path, carve` | **Indexed**: `carve_guid`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `time` | `BIGINT` | - | Time at which the carve was kicked off |
| `sha256` | `TEXT` | - | A SHA256 sum of the carved archive |
| `size` | `BIGINT` | - | Size in bytes of the carved archive |
| `path` | `TEXT` | `ADDITIONAL` | The path of the requested carve |
| `status` | `TEXT` | - | Status of the carve, can be STARTING, PENDING, SUCCESS, or FAILED |
| `carve_guid` | `TEXT` | `INDEX` | Identifying value of the carve session |
| `request_id` | `TEXT` | - | Identifying value of the carve request (e.g., scheduled query name, distributed request, etc) |
| `carve` | `INTEGER` | `ADDITIONAL` | Set this value to '1' to start a file carve |

#### `device_file`
Similar to the file table, but use TSK and allow block address access. (**Scope**: Cross-platform (`sleuthkit/device_file.table`: `linux, macos, windows`) | **Required `WHERE`**: `device, partition` | **Additional filters**: `path` | **Indexed**: `device, partition, inode`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `device` | `TEXT` | `REQUIRED`, `INDEX` | Absolute file path to device node |
| `partition` | `TEXT` | `REQUIRED`, `INDEX` | A partition number |
| `path` | `TEXT` | `ADDITIONAL` | A logical path within the device node |
| `filename` | `TEXT` | - | Name portion of file path |
| `inode` | `BIGINT` | `INDEX` | Filesystem inode number |
| `uid` | `BIGINT` | - | Owning user ID |
| `gid` | `BIGINT` | - | Owning group ID |
| `mode` | `TEXT` | - | Permission bits |
| `size` | `BIGINT` | - | Size of file in bytes |
| `block_size` | `INTEGER` | - | Block size of filesystem |
| `atime` | `BIGINT` | - | Last access time |
| `mtime` | `BIGINT` | - | Last modification time |
| `ctime` | `BIGINT` | - | Creation time |
| `hard_links` | `INTEGER` | - | Number of hard links |
| `type` | `TEXT` | - | File status |

#### `device_hash`
Similar to the hash table, but use TSK and allow block address access. (**Scope**: Cross-platform (`sleuthkit/device_hash.table`: `linux, macos, windows`) | **Required `WHERE`**: `device, partition, inode`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `device` | `TEXT` | `REQUIRED` | Absolute file path to device node |
| `partition` | `TEXT` | `REQUIRED` | A partition number |
| `inode` | `BIGINT` | `REQUIRED` | Filesystem inode number |
| `md5` | `TEXT` | - | MD5 hash of provided inode data |
| `sha1` | `TEXT` | - | SHA1 hash of provided inode data |
| `sha256` | `TEXT` | - | SHA256 hash of provided inode data |

#### `device_partitions`
Use TSK to enumerate details about partitions on a disk device. (**Scope**: Cross-platform (`sleuthkit/device_partitions.table`: `linux, macos, windows`) | **Required `WHERE`**: `device`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `device` | `TEXT` | `REQUIRED` | Absolute file path to device node |
| `partition` | `INTEGER` | - | A partition number or description |
| `label` | `TEXT` | - | The partition name as stored in the partition table |
| `type` | `TEXT` | - | Filesystem type if recognized, otherwise, 'meta', 'normal', or 'unallocated' |
| `offset` | `BIGINT` | - | Byte offset from the start of the volume |
| `blocks_size` | `BIGINT` | - | Byte size of each block |
| `blocks` | `BIGINT` | - | Number of blocks |
| `inodes` | `BIGINT` | - | Number of meta nodes |
| `flags` | `INTEGER` | - | Value that describes the partition (TSK_VS_PART_FLAG_ENUM) |

### 6. Drivers, Updates, Patches & Installed Software

#### `drivers`
Details for in-use Windows device drivers. This does not display installed but unused drivers. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `device_id` | `TEXT` | - | Device ID |
| `device_name` | `TEXT` | - | Device name |
| `image` | `TEXT` | - | Path to driver image file |
| `description` | `TEXT` | - | Driver description |
| `service` | `TEXT` | - | Driver service name, if one exists |
| `service_key` | `TEXT` | - | Driver service registry key |
| `version` | `TEXT` | - | Driver version |
| `inf` | `TEXT` | - | Associated inf file |
| `class` | `TEXT` | - | Device/driver class name |
| `provider` | `TEXT` | - | Driver provider |
| `manufacturer` | `TEXT` | - | Device manufacturer |
| `driver_key` | `TEXT` | - | Driver key |
| `date` | `BIGINT` | - | Driver date |
| `signed` | `INTEGER` | - | Whether the driver is signed or not |

#### `patches`
Lists all the patches applied. Note: This does not include patches applied via MSI or downloaded from Windows Update (e.g. Service Packs). (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `csname` | `TEXT` | - | The name of the host the patch is installed on. |
| `hotfix_id` | `TEXT` | - | The KB ID of the patch. |
| `caption` | `TEXT` | - | Short description of the patch. |
| `description` | `TEXT` | - | Fuller description of the patch. |
| `fix_comments` | `TEXT` | - | Additional comments about the patch. |
| `installed_by` | `TEXT` | - | The system context in which the patch as installed. |
| `install_date` | `TEXT` | - | Indicates when the patch was installed. Lack of a value does not indicate that the patch was not installed. |
| `installed_on` | `TEXT` | - | The date when the patch was installed. |

#### `windows_update_history`
Provides the history of the windows update events. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `client_app_id` | `TEXT` | - | Identifier of the client application that processed an update |
| `date` | `BIGINT` | - | Date and the time an update was applied |
| `description` | `TEXT` | - | Description of an update |
| `hresult` | `BIGINT` | - | HRESULT value that is returned from the operation on an update |
| `operation` | `TEXT` | - | Operation on an update |
| `result_code` | `TEXT` | - | Result of an operation on an update |
| `server_selection` | `TEXT` | - | Value that indicates which server provided an update |
| `service_id` | `TEXT` | - | Service identifier of an update service that is not a Windows update |
| `support_url` | `TEXT` | - | Hyperlink to the language-specific support information for an update |
| `title` | `TEXT` | - | Title of an update |
| `update_id` | `TEXT` | - | Revision-independent identifier of an update |
| `update_revision` | `BIGINT` | - | Revision number of an update |

#### `windows_optional_features`
Lists names and installation states of windows features. Maps to Win32_OptionalFeature WMI class. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Name of the feature |
| `caption` | `TEXT` | - | Caption of feature in settings UI |
| `state` | `INTEGER` | - | Installation state value. 1 == Enabled, 2 == Disabled, 3 == Absent |
| `statename` | `TEXT` | - | Installation state name. 'Enabled','Disabled','Absent' |

#### `programs` (Aliases: `programs_and_features`)
Represents products as they are installed by Windows Installer. A product generally correlates to one installation package on Windows. Some fields may be blank as Windows installation details are left to the discretion of the product author. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Commonly used product name. |
| `version` | `TEXT` | - | Product version information. |
| `install_location` | `TEXT` | - | The installation location directory of the product. |
| `install_source` | `TEXT` | - | The installation source of the product. |
| `language` | `TEXT` | - | The language of the product. |
| `publisher` | `TEXT` | - | Name of the product supplier. |
| `uninstall_string` | `TEXT` | - | Path and filename of the uninstaller. |
| `install_date` | `TEXT` | - | Date that this product was installed on the system. |
| `identifying_number` | `TEXT` | - | Product identification such as a serial number on software, or a die number on a hardware chip. |
| `package_family_name` | `TEXT` | - | A combination of PackageName and PublisherHash that is used to uniquely identify applications across versions and architectures. |
| `upgrade_code` | `TEXT` | - | Specific to MSI applications, a GUID used to identify a product suite across multiple versions. |

#### `chocolatey_packages`
Chocolatey packages installed in a system. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Package display name |
| `version` | `TEXT` | - | Package-supplied version |
| `summary` | `TEXT` | - | Package-supplied summary |
| `author` | `TEXT` | - | Optional package author |
| `license` | `TEXT` | - | License under which package is launched |
| `path` | `TEXT` | - | Path at which this package resides |

#### `python_packages`
Python packages installed in a system. NOTE: when querying on windows, even without a users cross join, all user installed python packages will be returned. (**Scope**: Cross-platform (`python_packages.table`: `linux, macos, windows`) | **Indexed**: `uid, directory` | **Attributes**: `user_data=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Package display name |
| `uid` | `BIGINT` | `INDEX` | The local user that owns the python package |
| `version` | `TEXT` | - | Package-supplied version |
| `summary` | `TEXT` | - | Package-supplied summary |
| `author` | `TEXT` | - | Optional package author |
| `license` | `TEXT` | - | License under which package is launched |
| `path` | `TEXT` | - | Path at which this module resides |
| `directory` | `TEXT` | `INDEX`, `OPTIMIZED` | Directory where Python modules are located |

#### `npm_packages`
Node packages installed in a system. (**Scope**: Cross-platform (`npm_packages.table`: `linux, macos, windows`) | **Additional filters**: `max_depth` | **Indexed**: `directory`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Package display name |
| `version` | `TEXT` | - | Package-supplied version |
| `description` | `TEXT` | - | Package-supplied description |
| `author` | `TEXT` | - | Package-supplied author |
| `license` | `TEXT` | - | License under which package is launched |
| `homepage` | `TEXT` | - | Package supplied homepage |
| `path` | `TEXT` | - | Path at which this module resides |
| `directory` | `TEXT` | `INDEX`, `OPTIMIZED` | Directory where node_modules are located |
| `depth` | `INTEGER` | - | Nesting depth of the package (0 = direct dependency) |
| `max_depth` | `INTEGER` | `ADDITIONAL`, `HIDDEN` | Maximum depth to search for nested packages (default 100, -1 = unlimited) |

#### `vscode_extensions`
Lists all vscode extensions. (**Scope**: Cross-platform (`vscode_extensions.table`: `linux, macos, windows`) | **Additional filters**: `uid` | **Attributes**: `user_data=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Extension Name |
| `uuid` | `TEXT` | - | Extension UUID |
| `version` | `TEXT` | - | Extension version |
| `path` | `TEXT` | - | Extension path |
| `publisher` | `TEXT` | - | Publisher Name |
| `publisher_id` | `TEXT` | - | Publisher ID |
| `installed_at` | `BIGINT` | - | Installed Timestamp |
| `prerelease` | `INTEGER` | - | Pre release version |
| `uid` | `BIGINT` | `ADDITIONAL`, `OPTIMIZED` | The local user that owns the plugin |
| `vscode_edition` | `TEXT` | - | The VSCode edition (vscode, vscode_insiders, vscodium, vscodium_insiders, cursor, windsurf, trae) |

#### `jetbrains_plugins`
JetBrains IDEs plugins. (**Scope**: Cross-platform (`jetbrains_plugins.table`: `linux, macos, windows`) | **Indexed**: `uid` | **Attributes**: `user_data=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `product_type` | `TEXT` | - | The product type (Valid values: CLion, DataGrip, GoLand, IntelliJIdea, IntelliJIdeaCommunityEdition, PhpStorm, PyCharm, PyCharmCommunityEdition, ReSharper, Rider, RubyMine, RustRover, WebStorm) |
| `uid` | `BIGINT` | `INDEX` | The local user that owns the plugin |
| `name` | `TEXT` | - | Name of the plugin (Title Case) |
| `version` | `TEXT` | - | Version of the plugin |
| `vendor` | `TEXT` | - | The vendor name or organization id that authored the plugin |
| `path` | `TEXT` | - | The path on the filesystem for the plugin. This may be a folder or a jar filename |

### 7. Browser Extensions & Addons

#### `chrome_extensions`
Chrome-based browser extensions. (**Scope**: Cross-platform (`chrome_extensions.table`: `linux, macos, windows`) | **Indexed**: `uid` | **Attributes**: `user_data=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `browser_type` | `TEXT` | - | The browser type (Valid values: chrome, chrome_beta, chrome_dev, chrome_canary, chromium, opera, yandex, brave, brave_beta, brave_nightly, edge, edge_beta, edge_dev, edge_canary, vivaldi, arc, dia, comet) |
| `uid` | `BIGINT` | `INDEX`, `OPTIMIZED` | The local user that owns the extension |
| `name` | `TEXT` | - | Extension display name |
| `profile` | `TEXT` | - | The name of the Chrome profile that contains this extension |
| `profile_path` | `TEXT` | - | The profile path |
| `referenced_identifier` | `TEXT` | - | Extension identifier, as specified by the preferences file. Empty if the extension is not in the profile. |
| `identifier` | `TEXT` | - | Extension identifier, computed from its manifest. Empty in case of error. |
| `version` | `TEXT` | - | Extension-supplied version |
| `description` | `TEXT` | - | Extension-optional description |
| `default_locale` | `TEXT` | alias: `locale` | Default locale supported by extension |
| `current_locale` | `TEXT` | - | Current locale supported by extension |
| `update_url` | `TEXT` | - | Extension-supplied update URI |
| `author` | `TEXT` | - | Optional extension author |
| `persistent` | `INTEGER` | - | 1 If extension is persistent across all tabs else 0 |
| `path` | `TEXT` | - | Path to extension folder |
| `permissions` | `TEXT` | - | The permissions required by the extension |
| `permissions_json` | `TEXT` | `HIDDEN` | The JSON-encoded permissions required by the extension |
| `optional_permissions` | `TEXT` | - | The permissions optionally required by the extensions |
| `optional_permissions_json` | `TEXT` | `HIDDEN` | The JSON-encoded permissions optionally required by the extensions |
| `manifest_hash` | `TEXT` | - | The SHA256 hash of the manifest.json file |
| `referenced` | `BIGINT` | - | 1 if this extension is referenced by the Preferences file of the profile |
| `from_webstore` | `TEXT` | - | True if this extension was installed from the web store |
| `state` | `TEXT` | - | 1 if this extension is enabled |
| `install_time` | `TEXT` | - | Extension install time, in its original Webkit format |
| `install_timestamp` | `BIGINT` | - | Extension install time, converted to unix time |
| `manifest_json` | `TEXT` | `HIDDEN` | The manifest file of the extension |
| `key` | `TEXT` | `HIDDEN` | The extension key, from the manifest file |

#### `chrome_extension_content_scripts`
Chrome browser extension content scripts. (**Scope**: Cross-platform (`chrome_extension_content_scripts.table`: `linux, macos, windows`) | **Indexed**: `uid` | **Attributes**: `user_data=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `browser_type` | `TEXT` | - | The browser type (Valid values: chrome, chromium, opera, yandex, brave) |
| `uid` | `BIGINT` | `INDEX`, `OPTIMIZED` | The local user that owns the extension |
| `identifier` | `TEXT` | - | Extension identifier |
| `version` | `TEXT` | - | Extension-supplied version |
| `script` | `TEXT` | - | The content script used by the extension |
| `match` | `TEXT` | - | The pattern that the script is matched against |
| `profile_path` | `TEXT` | - | The profile path |
| `path` | `TEXT` | - | Path to extension folder |
| `referenced` | `BIGINT` | - | 1 if this extension is referenced by the Preferences file of the profile |

#### `firefox_addons`
Firefox browser extensions, webapps, and addons. (**Scope**: Cross-platform (`firefox_addons.table`: `linux, macos, windows`) | **Additional filters**: `uid` | **Indexed**: `identifier` | **Attributes**: `user_data=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `uid` | `BIGINT` | `ADDITIONAL`, `OPTIMIZED` | The local user that owns the addon |
| `name` | `TEXT` | - | Addon display name |
| `identifier` | `TEXT` | `INDEX` | Addon identifier |
| `creator` | `TEXT` | - | Addon-supported creator string |
| `type` | `TEXT` | - | Extension, addon, webapp |
| `version` | `TEXT` | - | Addon-supplied version string |
| `description` | `TEXT` | - | Addon-supplied description string |
| `source_url` | `TEXT` | - | URL that installed the addon |
| `visible` | `INTEGER` | - | 1 If the addon is shown in browser else 0 |
| `active` | `INTEGER` | - | 1 If the addon is active else 0 |
| `disabled` | `INTEGER` | - | 1 If the addon is application-disabled else 0 |
| `autoupdate` | `INTEGER` | - | 1 If the addon applies background updates else 0 |
| `location` | `TEXT` | - | Global, profile location |
| `path` | `TEXT` | - | Path to plugin bundle |

#### `ie_extensions`
Internet Explorer browser extensions. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Extension display name |
| `registry_path` | `TEXT` | - | Extension identifier |
| `version` | `TEXT` | - | Version of the executable |
| `path` | `TEXT` | - | Path to executable |

### 8. Networking, Firewall, DNS & Connectivity

#### `listening_ports`
Processes with listening (bound) network sockets/ports. (**Scope**: Cross-platform (`listening_ports.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `pid` | `INTEGER` | - | Process (or thread) ID |
| `port` | `INTEGER` | - | Transport layer port |
| `protocol` | `INTEGER` | - | Transport protocol (TCP/UDP) |
| `family` | `INTEGER` | - | Network protocol (IPv4, IPv6) |
| `address` | `TEXT` | - | Specific address for bind |
| `fd` | `BIGINT` | - | Socket file descriptor number |
| `socket` | `BIGINT` | - | Socket handle or inode number |
| `path` | `TEXT` | - | Path for UNIX domain sockets |

#### `process_open_sockets`
Processes which have open network sockets on the system. (**Scope**: Cross-platform (`process_open_sockets.table`: `linux, macos, windows`) | **Additional filters**: `pid`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `pid` | `INTEGER` | `ADDITIONAL` | Process (or thread) ID |
| `fd` | `BIGINT` | - | Socket file descriptor number |
| `socket` | `BIGINT` | - | Socket handle or inode number |
| `family` | `INTEGER` | - | Network protocol (IPv4, IPv6) |
| `protocol` | `INTEGER` | - | Transport protocol (TCP/UDP) |
| `local_address` | `TEXT` | - | Socket local address |
| `remote_address` | `TEXT` | - | Socket remote address |
| `local_port` | `INTEGER` | - | Socket local port |
| `remote_port` | `INTEGER` | - | Socket remote port |
| `path` | `TEXT` | - | For UNIX sockets (family=AF_UNIX), the domain path |
| `state` | `TEXT` | - | TCP socket state |

#### `interface_addresses`
Network interfaces and relevant metadata. (**Scope**: Cross-platform (`interface_addresses.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `interface` | `TEXT` | - | Interface name |
| `address` | `TEXT` | - | Specific address for interface |
| `mask` | `TEXT` | - | Interface netmask |
| `broadcast` | `TEXT` | - | Broadcast address for the interface |
| `point_to_point` | `TEXT` | - | PtP address for the interface |
| `type` | `TEXT` | - | Type of address. One of dhcp, manual, auto, other, unknown |
| `friendly_name` | `TEXT` | `WINDOWS-EXT` | The friendly display name of the interface. |

#### `interface_details`
Detailed information and stats of network interfaces. (**Scope**: Cross-platform (`interface_details.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `interface` | `TEXT` | - | Interface name |
| `mac` | `TEXT` | - | MAC of interface (optional) |
| `type` | `INTEGER` | - | Interface type (includes virtual) |
| `mtu` | `INTEGER` | - | Network MTU |
| `metric` | `INTEGER` | - | Metric based on the speed of the interface |
| `flags` | `INTEGER` | - | Flags (netdevice) for the device |
| `ipackets` | `BIGINT` | - | Input packets |
| `opackets` | `BIGINT` | - | Output packets |
| `ibytes` | `BIGINT` | - | Input bytes |
| `obytes` | `BIGINT` | - | Output bytes |
| `ierrors` | `BIGINT` | - | Input errors |
| `oerrors` | `BIGINT` | - | Output errors |
| `idrops` | `BIGINT` | - | Input drops |
| `odrops` | `BIGINT` | - | Output drops |
| `collisions` | `BIGINT` | - | Packet Collisions detected |
| `last_change` | `BIGINT` | - | Time of last device modification (optional) |
| `friendly_name` | `TEXT` | `WINDOWS-EXT` | The friendly display name of the interface. |
| `description` | `TEXT` | `WINDOWS-EXT` | Short description of the object a one-line string. |
| `manufacturer` | `TEXT` | `WINDOWS-EXT` | Name of the network adapter's manufacturer. |
| `connection_id` | `TEXT` | `WINDOWS-EXT` | Name of the network connection as it appears in the Network Connections Control Panel program. |
| `connection_status` | `TEXT` | `WINDOWS-EXT` | State of the network adapter connection to the network. |
| `enabled` | `INTEGER` | `WINDOWS-EXT` | Indicates whether the adapter is enabled or not. |
| `physical_adapter` | `INTEGER` | `WINDOWS-EXT` | Indicates whether the adapter is a physical or a logical adapter. |
| `speed` | `INTEGER` | `WINDOWS-EXT` | Estimate of the current bandwidth in bits per second. |
| `service` | `TEXT` | `WINDOWS-EXT` | The name of the service the network adapter uses. |
| `dhcp_enabled` | `INTEGER` | `WINDOWS-EXT` | If TRUE, the dynamic host configuration protocol (DHCP) server automatically assigns an IP address to the computer system when establishing a network connection. |
| `dhcp_lease_expires` | `TEXT` | `WINDOWS-EXT` | Expiration date and time for a leased IP address that was assigned to the computer by the dynamic host configuration protocol (DHCP) server. |
| `dhcp_lease_obtained` | `TEXT` | `WINDOWS-EXT` | Date and time the lease was obtained for the IP address assigned to the computer by the dynamic host configuration protocol (DHCP) server. |
| `dhcp_server` | `TEXT` | `WINDOWS-EXT` | IP address of the dynamic host configuration protocol (DHCP) server. |
| `dns_domain` | `TEXT` | `WINDOWS-EXT` | Organization name followed by a period and an extension that indicates the type of organization, such as 'microsoft.com'. |
| `dns_domain_suffix_search_order` | `TEXT` | `WINDOWS-EXT` | Array of DNS domain suffixes to be appended to the end of host names during name resolution. |
| `dns_host_name` | `TEXT` | `WINDOWS-EXT` | Host name used to identify the local computer for authentication by some utilities. |
| `dns_server_search_order` | `TEXT` | `WINDOWS-EXT` | Array of server IP addresses to be used in querying for DNS servers. |

#### `routes`
The active route table for the host system. (**Scope**: Cross-platform (`routes.table`: `linux, macos, windows`) | **Additional filters**: `type` | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `destination` | `TEXT` | - | Destination IP address |
| `netmask` | `INTEGER` | - | Netmask length |
| `gateway` | `TEXT` | - | Route gateway |
| `source` | `TEXT` | - | Route source |
| `flags` | `INTEGER` | - | Flags to describe route |
| `interface` | `TEXT` | - | Route local interface |
| `mtu` | `INTEGER` | - | Maximum Transmission Unit for the route |
| `metric` | `INTEGER` | - | Cost of route. Lowest is preferred |
| `type` | `TEXT` | `ADDITIONAL` | Type of route |

#### `arp_cache`
Address resolution cache, both static and dynamic (from ARP, NDP). (**Scope**: Cross-platform (`arp_cache.table`: `linux, macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `address` | `TEXT` | - | IPv4 address target |
| `mac` | `TEXT` | - | MAC address of broadcasted address |
| `interface` | `TEXT` | - | Interface of the network for the MAC |
| `permanent` | `TEXT` | - | 1 for true, 0 for false |

#### `connectivity`
Provides the overall system's network state. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `disconnected` | `INTEGER` | - | True if the all interfaces are not connected to any network |
| `ipv4_no_traffic` | `INTEGER` | - | True if any interface is connected via IPv4, but has seen no traffic |
| `ipv6_no_traffic` | `INTEGER` | - | True if any interface is connected via IPv6, but has seen no traffic |
| `ipv4_subnet` | `INTEGER` | - | True if any interface is connected to the local subnet via IPv4 |
| `ipv4_local_network` | `INTEGER` | - | True if any interface is connected to a routed network via IPv4 |
| `ipv4_internet` | `INTEGER` | - | True if any interface is connected to the Internet via IPv4 |
| `ipv6_subnet` | `INTEGER` | - | True if any interface is connected to the local subnet via IPv6 |
| `ipv6_local_network` | `INTEGER` | - | True if any interface is connected to a routed network via IPv6 |
| `ipv6_internet` | `INTEGER` | - | True if any interface is connected to the Internet via IPv6 |

#### `dns_cache`
Enumerate the DNS cache using the undocumented DnsGetCacheDataTable function in dnsapi.dll. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | DNS record name |
| `type` | `TEXT` | - | DNS record type |
| `flags` | `INTEGER` | - | DNS record flags |

#### `dns_lookup_events`
DNS lookups performed through the Windows DNS stack. (**Scope**: Windows-only (`specs/windows/`) | **Additional filters**: `time` | **Attributes**: `event_subscriber=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `eid` | `INTEGER` | `HIDDEN` | Event ID |
| `time` | `BIGINT` | `ADDITIONAL`, `HIDDEN` | Event timestamp in Unix format |
| `time_windows` | `BIGINT` | `HIDDEN` | Event timestamp in Windows format |
| `datetime` | `DATETIME` | - | Event timestamp in DATETIME format |
| `pid` | `BIGINT` | - | Process ID of process making the lookup |
| `path` | `TEXT` | - | Path to binary of process making the lookup (sometimes unavailable for very short-lived processes) |
| `username` | `TEXT` | - | User rights - primary token username |
| `name` | `TEXT` | - | Name being queried in lookup |
| `type` | `TEXT` | - | DNS record type of lookup as string |
| `type_id` | `INTEGER` | - | Integer type ID for record type |
| `status` | `INTEGER` | - | Response status code |
| `response` | `TEXT` | - | Results returned by lookup |

#### `windows_firewall_rules`
Provides the list of Windows firewall rules. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Friendly name of the rule |
| `app_name` | `TEXT` | - | Friendly name of the application to which the rule applies |
| `action` | `TEXT` | - | Action for the rule or default setting |
| `enabled` | `INTEGER` | - | 1 if the rule is enabled |
| `grouping` | `TEXT` | - | Group to which an individual rule belongs |
| `direction` | `TEXT` | - | Direction of traffic for which the rule applies |
| `protocol` | `TEXT` | - | IP protocol of the rule |
| `local_addresses` | `TEXT` | - | Local addresses for the rule |
| `remote_addresses` | `TEXT` | - | Remote addresses for the rule |
| `local_ports` | `TEXT` | - | Local ports for the rule |
| `remote_ports` | `TEXT` | - | Remote ports for the rule |
| `icmp_types_codes` | `TEXT` | - | ICMP types and codes for the rule |
| `profile_domain` | `INTEGER` | - | 1 if the rule profile type is domain |
| `profile_private` | `INTEGER` | - | 1 if the rule profile type is private |
| `profile_public` | `INTEGER` | - | 1 if the rule profile type is public |
| `service_name` | `TEXT` | - | Service name property of the application |

#### `etc_hosts` (Aliases: `hosts`)
Line-parsed /etc/hosts. (**Scope**: Cross-platform (`etc_hosts.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `address` | `TEXT` | - | IP address mapping |
| `hostnames` | `TEXT` | - | Raw hosts mapping |

#### `etc_protocols`
Line-parsed /etc/protocols. (**Scope**: Cross-platform (`etc_protocols.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Protocol name |
| `number` | `INTEGER` | - | Protocol number |
| `alias` | `TEXT` | - | Protocol alias |
| `comment` | `TEXT` | - | Comment with protocol description |

#### `etc_services`
Line-parsed /etc/services. (**Scope**: Cross-platform (`etc_services.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Service name |
| `port` | `INTEGER` | - | Service port number |
| `protocol` | `TEXT` | - | Transport protocol (TCP/UDP) |
| `aliases` | `TEXT` | - | Optional space separated list of other names for a service |
| `comment` | `TEXT` | - | Optional comment for a service. |

#### `curl`
Perform an http request and return stats about it. (**Scope**: Cross-platform (`curl.table`: `linux, macos, windows`) | **Required `WHERE`**: `url` | **Additional filters**: `user_agent` | **Indexed**: `url`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `url` | `TEXT` | `REQUIRED`, `INDEX`, `OPTIMIZED` | The url for the request |
| `method` | `TEXT` | - | The HTTP method for the request |
| `user_agent` | `TEXT` | `ADDITIONAL` | The user-agent string to use for the request |
| `response_code` | `INTEGER` | - | The HTTP status code for the response |
| `round_trip_time` | `BIGINT` | - | Time taken to complete the request |
| `bytes` | `BIGINT` | - | Number of bytes in the response |
| `result` | `TEXT` | - | The HTTP response body |

#### `curl_certificate`
Inspect TLS certificates by connecting to input hostnames. (**Scope**: Cross-platform (`curl_certificate.table`: `linux, macos, windows`) | **Required `WHERE`**: `hostname` | **Additional filters**: `dump_certificate, timeout`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `hostname` | `TEXT` | `REQUIRED`, `OPTIMIZED` | Hostname to CURL (domain[:port], e.g. osquery.io) |
| `common_name` | `TEXT` | - | Common name of company issued to |
| `organization` | `TEXT` | - | Organization issued to |
| `organization_unit` | `TEXT` | - | Organization unit issued to |
| `serial_number` | `TEXT` | - | Certificate serial number |
| `issuer_common_name` | `TEXT` | - | Issuer common name |
| `issuer_organization` | `TEXT` | - | Issuer organization |
| `issuer_organization_unit` | `TEXT` | - | Issuer organization unit |
| `valid_from` | `TEXT` | - | Period of validity start date |
| `valid_to` | `TEXT` | - | Period of validity end date |
| `sha256_fingerprint` | `TEXT` | - | SHA-256 fingerprint |
| `sha1_fingerprint` | `TEXT` | - | SHA1 fingerprint |
| `version` | `INTEGER` | - | Version Number |
| `signature_algorithm` | `TEXT` | - | Signature Algorithm |
| `signature` | `TEXT` | - | Signature |
| `subject_key_identifier` | `TEXT` | - | Subject Key Identifier |
| `authority_key_identifier` | `TEXT` | - | Authority Key Identifier |
| `key_usage` | `TEXT` | - | Usage of key in certificate |
| `extended_key_usage` | `TEXT` | - | Extended usage of key in certificate |
| `policies` | `TEXT` | - | Certificate Policies |
| `subject_alternative_names` | `TEXT` | - | Subject Alternative Name |
| `issuer_alternative_names` | `TEXT` | - | Issuer Alternative Name |
| `info_access` | `TEXT` | - | Authority Information Access |
| `subject_info_access` | `TEXT` | - | Subject Information Access |
| `policy_mappings` | `TEXT` | - | Policy Mappings |
| `has_expired` | `INTEGER` | - | 1 if the certificate has expired, 0 otherwise |
| `basic_constraint` | `TEXT` | - | Basic Constraints |
| `name_constraints` | `TEXT` | - | Name Constraints |
| `policy_constraints` | `TEXT` | - | Policy Constraints |
| `dump_certificate` | `INTEGER` | `ADDITIONAL`, `HIDDEN` | Set this value to '1' to dump certificate |
| `timeout` | `INTEGER` | `ADDITIONAL`, `HIDDEN` | Set this value to the timeout in seconds to complete the TLS handshake (default 4s, use 0 for no timeout) |
| `pem` | `TEXT` | - | Certificate PEM format |
| `tls_version` | `TEXT` | - | TLS protocol version negotiated for the connection; empty if the handshake did not complete |
| `cipher_suite` | `TEXT` | - | IANA name of the cipher suite negotiated for the connection; empty if the handshake did not complete |
| `cipher_bits` | `INTEGER` | - | Number of secret/key bits used by the negotiated cipher suite; NULL if the handshake did not complete |

### 9. Users, Groups, Logon Sessions, Domain & Shares

#### `users`
Local user accounts (including domain accounts that have logged on locally (Windows)). (**Scope**: Cross-platform (`users.table`: `linux, macos, windows`) | **Additional filters**: `username` | **Indexed**: `uid, uuid`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `uid` | `BIGINT` | `INDEX` | User ID |
| `gid` | `BIGINT` | - | Group ID (unsigned) |
| `uid_signed` | `BIGINT` | - | User ID as int64 signed (Apple) |
| `gid_signed` | `BIGINT` | - | Default group ID as int64 signed (Apple) |
| `username` | `TEXT` | `ADDITIONAL` | Username |
| `description` | `TEXT` | - | Optional user description |
| `directory` | `TEXT` | - | User's home directory |
| `shell` | `TEXT` | - | User's configured default shell |
| `uuid` | `TEXT` | `INDEX` | User's UUID (Apple) or SID (Windows) |
| `type` | `TEXT` | `WINDOWS-EXT` | Whether the account is roaming (domain), local, or a system profile |

#### `groups`
Local system groups. (**Scope**: Cross-platform (`groups.table`: `linux, macos, windows`) | **Indexed**: `gid, group_sid`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `gid` | `BIGINT` | `INDEX` | Unsigned int64 group ID |
| `gid_signed` | `BIGINT` | - | A signed int64 version of gid |
| `groupname` | `TEXT` | - | Canonical local group name |
| `group_sid` | `TEXT` | `INDEX`, `WINDOWS-EXT` | Unique group ID |
| `comment` | `TEXT` | `WINDOWS-EXT` | Remarks or comments associated with the group |

#### `user_groups`
Local system user group relationships. (**Scope**: Cross-platform (`user_groups.table`: `linux, macos, windows`) | **Indexed**: `uid, gid`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `uid` | `BIGINT` | `INDEX`, `OPTIMIZED` | User ID |
| `gid` | `BIGINT` | `INDEX` | Group ID |

#### `logged_in_users`
Users with an active shell on the system. (**Scope**: Cross-platform (`logged_in_users.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `type` | `TEXT` | - | Login type |
| `user` | `TEXT` | - | User login name |
| `tty` | `TEXT` | - | Device name |
| `host` | `TEXT` | - | Remote hostname |
| `time` | `BIGINT` | - | Time entry was made |
| `pid` | `INTEGER` | - | Process (or thread) ID |
| `sid` | `TEXT` | `WINDOWS-EXT` | The user's unique security identifier |
| `registry_hive` | `TEXT` | `WINDOWS-EXT` | HKEY_USERS registry hive |

#### `logon_sessions`
Windows Logon Session. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `logon_id` | `INTEGER` | - | A locally unique identifier (LUID) that identifies a logon session. |
| `user` | `TEXT` | - | The account name of the security principal that owns the logon session. |
| `logon_domain` | `TEXT` | - | The name of the domain used to authenticate the owner of the logon session. |
| `authentication_package` | `TEXT` | - | The authentication package used to authenticate the owner of the logon session. |
| `logon_type` | `TEXT` | - | The logon method. |
| `session_id` | `INTEGER` | - | The Terminal Services session identifier. |
| `logon_sid` | `TEXT` | - | The user's security identifier (SID). |
| `logon_time` | `BIGINT` | - | The time the session owner logged on. |
| `logon_server` | `TEXT` | - | The name of the server used to authenticate the owner of the logon session. |
| `dns_domain_name` | `TEXT` | - | The DNS name for the owner of the logon session. |
| `upn` | `TEXT` | - | The user principal name (UPN) for the owner of the logon session. |
| `logon_script` | `TEXT` | - | The script used for logging on. |
| `profile_path` | `TEXT` | - | The home directory for the logon session. |
| `home_directory` | `TEXT` | - | The home directory for the logon session. |
| `home_directory_drive` | `TEXT` | - | The drive location of the home directory of the logon session. |

#### `ntdomains`
Display basic NT domain information of a Windows machine. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | The label by which the object is known. |
| `client_site_name` | `TEXT` | - | The name of the site where the domain controller is configured. |
| `dc_site_name` | `TEXT` | - | The name of the site where the domain controller is located. |
| `dns_forest_name` | `TEXT` | - | The name of the root of the DNS tree. |
| `domain_controller_address` | `TEXT` | - | The IP Address of the discovered domain controller. |
| `domain_controller_name` | `TEXT` | - | The name of the discovered domain controller. |
| `domain_name` | `TEXT` | - | The name of the domain. |
| `status` | `TEXT` | - | The current status of the domain object. |

#### `shared_resources`
Displays shared resources on a computer system running Windows. This may be a disk drive, printer, interprocess communication, or other sharable device. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `description` | `TEXT` | - | A textual description of the object |
| `install_date` | `TEXT` | - | Indicates when the object was installed. Lack of a value does not indicate that the object is not installed. |
| `status` | `TEXT` | - | String that indicates the current status of the object. |
| `allow_maximum` | `INTEGER` | - | Number of concurrent users for this resource has been limited. If True, the value in the MaximumAllowed property is ignored. |
| `maximum_allowed` | `BIGINT` | - | Limit on the maximum number of users allowed to use this resource concurrently. The value is only valid if the AllowMaximum property is set to FALSE. |
| `name` | `TEXT` | - | Alias given to a path set up as a share on a computer system running Windows. |
| `path` | `TEXT` | - | Local path of the Windows share. |
| `type` | `BIGINT` | - | Type of resource being shared. Types include: disk drives, print queues, interprocess communications (IPC), and general devices. |
| `type_name` | `TEXT` | - | Human readable value for the 'type' column |

#### `ssh_configs`
A table of parsed ssh_configs. (**Scope**: Cross-platform (`ssh_configs.table`: `linux, macos, windows`) | **Additional filters**: `uid` | **Attributes**: `user_data=True`, `no_pkey=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `uid` | `BIGINT` | `ADDITIONAL`, `OPTIMIZED` | The local owner of the ssh_config file |
| `block` | `TEXT` | - | The host or match block |
| `option` | `TEXT` | - | The option and value |
| `ssh_config_file` | `TEXT` | - | Path to the ssh_config file |

#### `user_ssh_keys`
Returns the private keys in the users ~/.ssh directory and whether or not they are encrypted. (**Scope**: Cross-platform (`user_ssh_keys.table`: `linux, macos, windows`) | **Additional filters**: `uid` | **Indexed**: `path` | **Attributes**: `user_data=True`, `no_pkey=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `uid` | `BIGINT` | `ADDITIONAL`, `OPTIMIZED` | The local user that owns the key file |
| `path` | `TEXT` | `INDEX` | Path to key file |
| `encrypted` | `INTEGER` | - | 1 if key is encrypted, 0 otherwise |
| `key_type` | `TEXT` | - | The type of the private key. One of [rsa, dsa, dh, ec, hmac, cmac], or the empty string. |
| `key_group_name` | `TEXT` | - | The group of the private key. Supported for a subset of key_types implemented by OpenSSL |
| `key_length` | `INTEGER` | - | The cryptographic length of the cryptosystem to which the private key belongs, in bits. -1 if unavailable |
| `key_security_bits` | `INTEGER` | - | The number of security bits of the private key, bits of security as defined in NIST SP800-57. -1 if unavailable |

### 10. Windows Security, Encryption, Certificates & YARA

#### `windows_security_center`
The health status of Window Security features. Health values can be "Good", "Poor". "Snoozed", "Not Monitored", and "Error". (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `firewall` | `TEXT` | - | The health of the monitored Firewall (see windows_security_products) |
| `autoupdate` | `TEXT` | - | The health of the Windows Autoupdate feature |
| `antivirus` | `TEXT` | - | The health of the monitored Antivirus solution (see windows_security_products) |
| `antispyware` | `TEXT` | `HIDDEN` | Deprecated (always 'Good'). |
| `internet_settings` | `TEXT` | - | The health of the Internet Settings |
| `windows_security_center_service` | `TEXT` | - | The health of the Windows Security Center Service |
| `user_account_control` | `TEXT` | - | The health of the User Account Control (UAC) capability in Windows |

#### `windows_security_products`
Enumeration of registered Windows security products. Note: Not compatible with Windows Server. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `type` | `TEXT` | - | Type of security product |
| `name` | `TEXT` | - | Name of product |
| `state` | `TEXT` | - | State of protection |
| `state_timestamp` | `TEXT` | - | Timestamp for the product state |
| `remediation_path` | `TEXT` | - | Remediation path |
| `signatures_up_to_date` | `INTEGER` | - | 1 if product signatures are up to date, else 0 |

#### `security_profile_info`
Information on the security profile of a given system by listing the system Account and Audit Policies. This table mimics the exported securitypolicy output from the secedit tool. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `minimum_password_age` | `INTEGER` | - | Determines the minimum number of days that a password must be used before the user can change it |
| `maximum_password_age` | `INTEGER` | - | Determines the maximum number of days that a password can be used before the client requires the user to change it |
| `minimum_password_length` | `INTEGER` | - | Determines the least number of characters that can make up a password for a user account |
| `password_complexity` | `INTEGER` | - | Determines whether passwords must meet a series of strong-password guidelines |
| `password_history_size` | `INTEGER` | - | Number of unique new passwords that must be associated with a user account before an old password can be reused |
| `lockout_bad_count` | `INTEGER` | - | Number of failed logon attempts after which a user account MUST be locked out |
| `logon_to_change_password` | `INTEGER` | - | Determines if logon session is required to change the password |
| `force_logoff_when_expire` | `INTEGER` | - | Determines whether SMB client sessions with the SMB server will be forcibly disconnected when the client's logon hours expire |
| `new_administrator_name` | `TEXT` | - | Determines the name of the Administrator account on the local computer |
| `new_guest_name` | `TEXT` | - | Determines the name of the Guest account on the local computer |
| `clear_text_password` | `INTEGER` | - | Determines whether passwords MUST be stored by using reversible encryption |
| `lsa_anonymous_name_lookup` | `INTEGER` | - | Determines if an anonymous user is allowed to query the local LSA policy |
| `enable_admin_account` | `INTEGER` | - | Determines whether the Administrator account on the local computer is enabled |
| `enable_guest_account` | `INTEGER` | - | Determines whether the Guest account on the local computer is enabled |
| `audit_system_events` | `INTEGER` | - | Determines whether the operating system MUST audit System Change, System Startup, System Shutdown, Authentication Component Load, and Loss or Excess of Security events |
| `audit_logon_events` | `INTEGER` | - | Determines whether the operating system MUST audit each instance of a user attempt to log on or log off this computer |
| `audit_object_access` | `INTEGER` | - | Determines whether the operating system MUST audit each instance of user attempts to access a non-Active Directory object that has its own SACL specified |
| `audit_privilege_use` | `INTEGER` | - | Determines whether the operating system MUST audit each instance of user attempts to exercise a user right |
| `audit_policy_change` | `INTEGER` | - | Determines whether the operating system MUST audit each instance of user attempts to change user rights assignment policy, audit policy, account policy, or trust policy |
| `audit_account_manage` | `INTEGER` | - | Determines whether the operating system MUST audit each event of account management on a computer |
| `audit_process_tracking` | `INTEGER` | - | Determines whether the operating system MUST audit process-related events |
| `audit_ds_access` | `INTEGER` | - | Determines whether the operating system MUST audit each instance of user attempts to access an Active Directory object that has its own system access control list (SACL) specified |
| `audit_account_logon` | `INTEGER` | - | Determines whether the operating system MUST audit each time this computer validates the credentials of an account |

#### `bitlocker_info`
Retrieve bitlocker status of the machine. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `device_id` | `TEXT` | - | ID of the encrypted drive. |
| `drive_letter` | `TEXT` | - | Drive letter of the encrypted drive. |
| `persistent_volume_id` | `TEXT` | - | Persistent ID of the drive. |
| `conversion_status` | `INTEGER` | - | The bitlocker conversion status of the drive. |
| `protection_status` | `INTEGER` | - | The bitlocker protection status of the drive. |
| `encryption_method` | `TEXT` | - | The encryption type of the device. |
| `protector_types` | `TEXT` | - | Protector types used to secure the volume's encryption key. |
| `version` | `INTEGER` | - | The FVE metadata version of the drive. |
| `percentage_encrypted` | `INTEGER` | - | The percentage of the drive that is encrypted. |
| `lock_status` | `INTEGER` | - | The accessibility status of the drive from Windows. |

#### `deviceguard_status` (Aliases: `hvci_status`)
Retrieve DeviceGuard info of the machine. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `version` | `TEXT` | - | The version number of the Device Guard build. |
| `instance_identifier` | `TEXT` | - | The instance ID of Device Guard. |
| `vbs_status` | `TEXT` | - | The status of the virtualization based security settings. Returns UNKNOWN if an error is encountered. |
| `code_integrity_policy_enforcement_status` | `TEXT` | - | The status of the code integrity policy enforcement settings. Returns UNKNOWN if an error is encountered. |
| `configured_security_services` | `TEXT` | - | The list of configured Device Guard services. Returns UNKNOWN if an error is encountered. |
| `running_security_services` | `TEXT` | - | The list of running Device Guard services. Returns UNKNOWN if an error is encountered. |
| `umci_policy_status` | `TEXT` | - | The status of the User Mode Code Integrity security settings. Returns UNKNOWN if an error is encountered. |

#### `tpm_info`
A table that lists the TPM related information. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `activated` | `INTEGER` | - | TPM is activated |
| `enabled` | `INTEGER` | - | TPM is enabled |
| `owned` | `INTEGER` | - | TPM is owned |
| `manufacturer_version` | `TEXT` | - | TPM version |
| `manufacturer_id` | `INTEGER` | - | TPM manufacturers ID |
| `manufacturer_name` | `TEXT` | - | TPM manufacturers name |
| `product_name` | `TEXT` | - | Product name of the TPM |
| `physical_presence_version` | `TEXT` | - | Version of the Physical Presence Interface |
| `spec_version` | `TEXT` | - | Trusted Computing Group specification that the TPM supports |

#### `secureboot`
Secure Boot UEFI Settings. (**Scope**: Cross-platform (`secureboot.table`: `linux, macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `secure_boot` | `INTEGER` | - | Whether secure boot is enabled |
| `setup_mode` | `INTEGER` | `WINDOWS-EXT` | Whether setup mode is enabled |

#### `authenticode`
File (executable, bundle, installer, disk) code signing status. (**Scope**: Windows-only (`specs/windows/`) | **Required `WHERE`**: `path`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `path` | `TEXT` | `REQUIRED`, `OPTIMIZED` | Must provide a path or directory |
| `original_program_name` | `TEXT` | - | The original program name that the publisher has signed |
| `serial_number` | `TEXT` | - | The certificate serial number |
| `issuer_name` | `TEXT` | - | The certificate issuer name |
| `subject_name` | `TEXT` | - | The certificate subject name |
| `result` | `TEXT` | - | The signature check result |

#### `certificates`
Certificate Authorities installed in Keychains/ca-bundles. (**Scope**: Cross-platform (`certificates.table`: `linux, macos, windows`) | **Additional filters**: `path` | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `common_name` | `TEXT` | - | Certificate CommonName |
| `subject` | `TEXT` | - | Certificate distinguished name (deprecated, use subject2) |
| `subject2` | `TEXT` | - | Certificate distinguished name |
| `issuer` | `TEXT` | - | Certificate issuer distinguished name (deprecated, use issuer2) |
| `issuer2` | `TEXT` | - | Certificate issuer distinguished name |
| `ca` | `INTEGER` | - | 1 if CA: true (certificate is an authority) else 0 |
| `self_signed` | `INTEGER` | - | 1 if self-signed, else 0 |
| `not_valid_before` | `DATETIME` | - | Lower bound of valid date |
| `not_valid_after` | `DATETIME` | - | Certificate expiration data |
| `signing_algorithm` | `TEXT` | - | Signing algorithm used |
| `key_algorithm` | `TEXT` | - | Key algorithm used |
| `key_strength` | `TEXT` | - | Key size used for RSA/DSA, or curve name |
| `key_usage` | `TEXT` | - | Certificate key usage and extended key usage |
| `subject_key_id` | `TEXT` | - | SKID an optionally included SHA1 |
| `authority_key_id` | `TEXT` | - | AKID an optionally included SHA1 |
| `sha1` | `TEXT` | - | SHA1 hash of the raw certificate contents |
| `path` | `TEXT` | `ADDITIONAL`, `OPTIMIZED` | Path to Keychain or PEM bundle |
| `serial` | `TEXT` | - | Certificate serial number |
| `sid` | `TEXT` | `WINDOWS-EXT` | SID |
| `store_location` | `TEXT` | `WINDOWS-EXT` | Certificate system store location |
| `store` | `TEXT` | `WINDOWS-EXT` | Certificate system store |
| `username` | `TEXT` | `WINDOWS-EXT` | Username |
| `store_id` | `TEXT` | `WINDOWS-EXT` | Exists for service/user stores. Contains raw store id provided by WinAPI. |

#### `carbon_black_info` (Aliases: `cb_info`)
Returns info about a Carbon Black sensor install. (**Scope**: Cross-platform (`carbon_black_info.table`: `linux, macos, windows`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `sensor_id` | `INTEGER` | - | Sensor ID of the Carbon Black sensor |
| `config_name` | `TEXT` | - | Sensor group |
| `collect_store_files` | `INTEGER` | - | If the sensor is configured to send back binaries to the Carbon Black server |
| `collect_module_loads` | `INTEGER` | - | If the sensor is configured to capture module loads |
| `collect_module_info` | `INTEGER` | - | If the sensor is configured to collect metadata of binaries |
| `collect_file_mods` | `INTEGER` | - | If the sensor is configured to collect file modification events |
| `collect_reg_mods` | `INTEGER` | - | If the sensor is configured to collect registry modification events |
| `collect_net_conns` | `INTEGER` | - | If the sensor is configured to collect network connections |
| `collect_processes` | `INTEGER` | - | If the sensor is configured to process events |
| `collect_cross_processes` | `INTEGER` | - | If the sensor is configured to cross process events |
| `collect_emet_events` | `INTEGER` | - | If the sensor is configured to EMET events |
| `collect_data_file_writes` | `INTEGER` | - | If the sensor is configured to collect non binary file writes |
| `collect_process_user_context` | `INTEGER` | - | If the sensor is configured to collect the user running a process |
| `collect_sensor_operations` | `INTEGER` | - | Unknown |
| `log_file_disk_quota_mb` | `INTEGER` | - | Event file disk quota in MB |
| `log_file_disk_quota_percentage` | `INTEGER` | - | Event file disk quota in a percentage |
| `protection_disabled` | `INTEGER` | - | If the sensor is configured to report tamper events |
| `sensor_ip_addr` | `TEXT` | - | IP address of the sensor |
| `sensor_backend_server` | `TEXT` | - | Carbon Black server |
| `event_queue` | `INTEGER` | - | Size in bytes of Carbon Black event files on disk |
| `binary_queue` | `INTEGER` | - | Size in bytes of binaries waiting to be sent to Carbon Black server |

#### `yara_file` (Aliases: `yara`)
Triggers one-off YARA query for files at the specified path. Additionally requires one of `sig_group`, `sigfile`, or `sigrule`. (**Scope**: Cross-platform (`yara_file.table`: `linux, macos, windows`) | **Required `WHERE`**: `path` | **Additional filters**: `sig_group, sigfile, sigrule, sigurl` | **Indexed**: `path`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `path` | `TEXT` | `REQUIRED`, `INDEX` | The path scanned |
| `matches` | `TEXT` | - | List of YARA matches |
| `count` | `INTEGER` | - | Number of YARA matches |
| `sig_group` | `TEXT` | `ADDITIONAL` | Signature group used |
| `sigfile` | `TEXT` | `ADDITIONAL` | Signature file used |
| `sigrule` | `TEXT` | `ADDITIONAL`, `HIDDEN` | Signature strings used |
| `strings` | `TEXT` | - | Matching strings |
| `tags` | `TEXT` | - | Matching tags |
| `sigurl` | `TEXT` | `ADDITIONAL`, `HIDDEN` | Signature url |

#### `yara_process`
Triggers one-off YARA query for process memory of the specified pid. Additionally requires one of `sig_group`, `sigfile`, or `sigrule`. (**Scope**: Cross-platform (`yara_process.table`: `linux, macos, windows`) | **Required `WHERE`**: `pid` | **Additional filters**: `sig_group, sigfile, sigrule, sigurl` | **Indexed**: `pid`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `pid` | `INTEGER` | `REQUIRED`, `INDEX` | The pid scanned (process memory) |
| `matches` | `TEXT` | - | List of YARA matches |
| `count` | `INTEGER` | - | Number of YARA matches |
| `sig_group` | `TEXT` | `ADDITIONAL` | Signature group used |
| `sigfile` | `TEXT` | `ADDITIONAL` | Signature file used |
| `sigrule` | `TEXT` | `ADDITIONAL`, `HIDDEN` | Signature strings used |
| `strings` | `TEXT` | - | Matching strings |
| `tags` | `TEXT` | - | Matching tags |
| `sigurl` | `TEXT` | `ADDITIONAL`, `HIDDEN` | Signature url |

#### `yara_events`
Track YARA matches for files specified in configuration data. (**Scope**: Cross-platform (`yara_events.table`: `linux, macos, windows`) | **Attributes**: `event_subscriber=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `target_path` | `TEXT` | - | The path scanned |
| `category` | `TEXT` | - | The category of the file |
| `action` | `TEXT` | - | Change action (UPDATE, REMOVE, etc) |
| `matches` | `TEXT` | - | List of YARA matches |
| `count` | `INTEGER` | - | Number of YARA matches |
| `strings` | `TEXT` | - | Matching strings |
| `tags` | `TEXT` | - | Matching tags |
| `time` | `BIGINT` | - | Time of the scan |
| `eid` | `TEXT` | `HIDDEN` | Event ID |

### 11. Windows Execution & User Activity Artifacts

#### `appcompat_shims`
Application Compatibility shims are a way to persist malware. This table presents the AppCompat Shim information from the registry in a nice format. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `executable` | `TEXT` | - | Name of the executable that is being shimmed. This is pulled from the registry. |
| `path` | `TEXT` | - | This is the path to the SDB database. |
| `description` | `TEXT` | - | Description of the SDB. |
| `install_time` | `INTEGER` | - | Install time of the SDB |
| `type` | `TEXT` | - | Type of the SDB database. |
| `sdb_id` | `TEXT` | - | Unique GUID of the SDB. |

#### `shimcache`
Application Compatibility Cache, contains artifacts of execution. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `entry` | `INTEGER` | - | Execution order. |
| `path` | `TEXT` | - | This is the path to the executed file. |
| `modified_time` | `INTEGER` | - | File Modified time. |
| `execution_flag` | `INTEGER` | - | Boolean Execution flag, 1 for execution, 0 for no execution, -1 for missing (this flag does not exist on Windows 10 and higher). |

#### `prefetch`
Prefetch files show metadata related to file execution. (**Scope**: Windows-only (`specs/windows/`) | **Additional filters**: `path`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `path` | `TEXT` | `ADDITIONAL`, `OPTIMIZED` | Prefetch file path. |
| `filename` | `TEXT` | - | Executable filename. |
| `hash` | `TEXT` | - | Prefetch CRC hash. |
| `last_run_time` | `INTEGER` | - | Most recent time application was run. |
| `other_run_times` | `TEXT` | - | Other execution times in prefetch file. |
| `run_count` | `INTEGER` | - | Number of times the application has been run. |
| `size` | `INTEGER` | - | Application file size. |
| `volume_serial` | `TEXT` | - | Volume serial number. |
| `volume_creation` | `TEXT` | - | Volume creation time. |
| `accessed_files_count` | `INTEGER` | - | Number of files accessed. |
| `accessed_directories_count` | `INTEGER` | - | Number of directories accessed. |
| `accessed_files` | `TEXT` | - | Files accessed by application within ten seconds of launch. |
| `accessed_directories` | `TEXT` | - | Directories accessed by application within ten seconds of launch. |
| `executable_path` | `TEXT` | - | Full path of the executable. |

#### `userassist`
UserAssist Registry Key tracks when a user executes an application from Windows Explorer. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `path` | `TEXT` | - | Application file path. |
| `last_execution_time` | `BIGINT` | - | Most recent time application was executed. |
| `count` | `INTEGER` | - | Number of times the application has been executed. |
| `sid` | `TEXT` | - | User SID. |

#### `background_activities_moderator`
Background Activities Moderator (BAM) tracks application execution. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `path` | `TEXT` | - | Application file path. |
| `last_execution_time` | `BIGINT` | - | Most recent time application was executed. |
| `sid` | `TEXT` | - | User SID. |

#### `shellbags`
Shows directories accessed via Windows Explorer. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `sid` | `TEXT` | - | User SID |
| `source` | `TEXT` | - | Shellbags source Registry file |
| `path` | `TEXT` | - | Directory name. |
| `modified_time` | `BIGINT` | - | Directory Modified time. |
| `created_time` | `BIGINT` | - | Directory Created time. |
| `accessed_time` | `BIGINT` | - | Directory Accessed time. |
| `mft_entry` | `BIGINT` | - | Directory master file table entry. |
| `mft_sequence` | `INTEGER` | - | Directory master file table sequence. |

#### `recent_files`
Recently files (as displayed in Start Menu or File Explorer). (**Scope**: Windows-only (`specs/windows/`) | **Indexed**: `uid` | **Attributes**: `user_data=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `uid` | `BIGINT` | `INDEX`, `OPTIMIZED` | The local user ID |
| `filename` | `TEXT` | - | The name of the file |
| `path` | `TEXT` | - | The full path of the file |
| `type` | `TEXT` | - | Display type for the file |
| `mtime` | `BIGINT` | - | Last modification time of the shortcut (usually corresponds to last opened time for the file) |
| `shortcut_path` | `TEXT` | - | Path to the shortcut where Windows stores the recent file data |

#### `office_mru`
View recently opened Office documents. (**Scope**: Windows-only (`specs/windows/`))

| Column | Type | Flags | Description |
|---|---|---|---|
| `application` | `TEXT` | - | Associated Office application |
| `version` | `TEXT` | - | Office application version number |
| `path` | `TEXT` | - | File path |
| `last_opened_time` | `BIGINT` | - | Most recent opened time file was opened |
| `sid` | `TEXT` | - | User SID |

### 12. Cloud Metadata & Osquery Internal Utilities

#### `azure_instance_metadata`
Azure instance metadata. (**Scope**: Cross-platform (`azure_instance_metadata.table`: `linux, macos, windows`) | **Indexed**: `vm_id` | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `location` | `TEXT` | - | Azure Region the VM is running in |
| `name` | `TEXT` | - | Name of the VM |
| `offer` | `TEXT` | - | Offer information for the VM image (Azure image gallery VMs only) |
| `publisher` | `TEXT` | - | Publisher of the VM image |
| `sku` | `TEXT` | - | SKU for the VM image |
| `version` | `TEXT` | - | Version of the VM image |
| `os_type` | `TEXT` | - | Linux or Windows |
| `platform_update_domain` | `TEXT` | - | Update domain the VM is running in |
| `platform_fault_domain` | `TEXT` | - | Fault domain the VM is running in |
| `vm_id` | `TEXT` | `INDEX` | Unique identifier for the VM |
| `vm_size` | `TEXT` | - | VM size |
| `subscription_id` | `TEXT` | - | Azure subscription for the VM |
| `resource_group_name` | `TEXT` | - | Resource group for the VM |
| `placement_group_id` | `TEXT` | - | Placement group for the VM scale set |
| `vm_scale_set_name` | `TEXT` | - | VM scale set name |
| `zone` | `TEXT` | - | Availability zone of the VM |

#### `azure_instance_tags`
Azure instance tags. (**Scope**: Cross-platform (`azure_instance_tags.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `vm_id` | `TEXT` | - | Unique identifier for the VM |
| `key` | `TEXT` | - | The tag key |
| `value` | `TEXT` | - | The tag value |

#### `ec2_instance_metadata`
EC2 instance metadata. (**Scope**: Cross-platform (`ec2_instance_metadata.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `instance_id` | `TEXT` | - | EC2 instance ID |
| `instance_type` | `TEXT` | - | EC2 instance type |
| `architecture` | `TEXT` | - | Hardware architecture of this EC2 instance |
| `region` | `TEXT` | - | AWS region in which this instance launched |
| `availability_zone` | `TEXT` | - | Availability zone in which this instance launched |
| `local_hostname` | `TEXT` | - | Private IPv4 DNS hostname of the first interface of this instance |
| `local_ipv4` | `TEXT` | - | Private IPv4 address of the first interface of this instance |
| `mac` | `TEXT` | - | MAC address for the first network interface of this EC2 instance |
| `security_groups` | `TEXT` | - | Comma separated list of security group names |
| `iam_arn` | `TEXT` | - | If there is an IAM role associated with the instance, contains instance profile ARN |
| `ami_id` | `TEXT` | - | AMI ID used to launch this EC2 instance |
| `reservation_id` | `TEXT` | - | ID of the reservation |
| `account_id` | `TEXT` | - | AWS account ID which owns this EC2 instance |
| `ssh_public_key` | `TEXT` | - | SSH public key. Only available if supplied at instance launch time |

#### `ec2_instance_tags`
EC2 instance tag key value pairs. (**Scope**: Cross-platform (`ec2_instance_tags.table`: `linux, macos, windows`) | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `instance_id` | `TEXT` | - | EC2 instance ID |
| `key` | `TEXT` | - | Tag key |
| `value` | `TEXT` | - | Tag value |

#### `ycloud_instance_metadata`
Yandex.Cloud instance metadata. (**Scope**: Cross-platform (`ycloud_instance_metadata.table`: `linux, macos, windows`) | **Indexed**: `instance_id, metadata_endpoint` | **Attributes**: `cacheable=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `instance_id` | `TEXT` | `INDEX` | Unique identifier for the VM |
| `folder_id` | `TEXT` | - | Folder identifier for the VM |
| `cloud_id` | `TEXT` | - | Cloud identifier for the VM |
| `name` | `TEXT` | - | Name of the VM |
| `description` | `TEXT` | - | Description of the VM |
| `hostname` | `TEXT` | - | Hostname of the VM |
| `zone` | `TEXT` | - | Availability zone of the VM |
| `ssh_public_key` | `TEXT` | - | SSH public key. Only available if supplied at instance launch time |
| `serial_port_enabled` | `TEXT` | - | Indicates if serial port is enabled for the VM |
| `metadata_endpoint` | `TEXT` | `INDEX` | Endpoint used to fetch VM metadata |

#### `osquery_events`
Information about the event publishers and subscribers. (**Scope**: Cross-platform (`utility/osquery_events.table`: `linux, macos, windows`) | **Attributes**: `utility=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Event publisher or subscriber name |
| `publisher` | `TEXT` | - | Name of the associated publisher |
| `type` | `TEXT` | - | Either publisher or subscriber |
| `subscriptions` | `INTEGER` | - | Number of subscriptions the publisher received or subscriber used |
| `events` | `INTEGER` | - | Number of events emitted or received since osquery started |
| `refreshes` | `INTEGER` | - | Publisher only: number of runloop restarts |
| `active` | `INTEGER` | - | 1 if the publisher or subscriber is active else 0 |

#### `osquery_extensions`
List of active osquery extensions. (**Scope**: Cross-platform (`utility/osquery_extensions.table`: `linux, macos, windows`) | **Attributes**: `utility=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `uuid` | `BIGINT` | - | The transient ID assigned for communication |
| `name` | `TEXT` | - | Extension's name |
| `version` | `TEXT` | - | Extension's version |
| `sdk_version` | `TEXT` | - | osquery SDK version used to build the extension |
| `path` | `TEXT` | - | Path of the extension's Thrift connection or library path |
| `type` | `TEXT` | - | SDK extension type: core, extension, or module |

#### `osquery_flags`
Configurable flags that modify osquery's behavior. (**Scope**: Cross-platform (`utility/osquery_flags.table`: `linux, macos, windows`) | **Attributes**: `utility=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | Flag name |
| `type` | `TEXT` | - | Flag type |
| `description` | `TEXT` | - | Flag description |
| `default_value` | `TEXT` | - | Flag default value |
| `value` | `TEXT` | - | Flag value |
| `shell_only` | `INTEGER` | - | Is the flag shell only? |

#### `osquery_info`
Top level information about the running version of osquery. (**Scope**: Cross-platform (`utility/osquery_info.table`: `linux, macos, windows`) | **Attributes**: `utility=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `pid` | `INTEGER` | - | Process (or thread/handle) ID |
| `uuid` | `TEXT` | - | Unique ID provided by the system |
| `instance_id` | `TEXT` | - | Unique, long-lived ID per instance of osquery |
| `version` | `TEXT` | - | osquery toolkit version |
| `config_hash` | `TEXT` | - | Hash of the working configuration state |
| `config_valid` | `INTEGER` | - | 1 if the config was loaded and considered valid, else 0 |
| `extensions` | `TEXT` | - | osquery extensions status |
| `build_platform` | `TEXT` | - | osquery toolkit build platform |
| `build_distro` | `TEXT` | - | osquery toolkit platform distribution name (os version) |
| `start_time` | `INTEGER` | - | UNIX time in seconds when the process started |
| `watcher` | `INTEGER` | - | Process (or thread/handle) ID of optional watcher process |
| `platform_mask` | `INTEGER` | - | The osquery platform bitmask |

#### `osquery_packs`
Information about the current query packs that are loaded in osquery. (**Scope**: Cross-platform (`utility/osquery_packs.table`: `linux, macos, windows`) | **Attributes**: `utility=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | The given name for this query pack |
| `platform` | `TEXT` | - | Platforms this query is supported on |
| `version` | `TEXT` | - | Minimum osquery version that this query will run on |
| `shard` | `INTEGER` | - | Shard restriction limit, 1-100, 0 meaning no restriction |
| `discovery_cache_hits` | `INTEGER` | - | The number of times that the discovery query used cached values since the last time the config was reloaded |
| `discovery_executions` | `INTEGER` | - | The number of times that the discovery queries have been executed since the last time the config was reloaded |
| `active` | `INTEGER` | - | Whether this pack is active (the version, platform and discovery queries match) yes=1, no=0. |

#### `osquery_registry`
List the osquery registry plugins. (**Scope**: Cross-platform (`utility/osquery_registry.table`: `linux, macos, windows`) | **Attributes**: `utility=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `registry` | `TEXT` | - | Name of the osquery registry |
| `name` | `TEXT` | - | Name of the plugin item |
| `owner_uuid` | `INTEGER` | - | Extension route UUID (0 for core) |
| `internal` | `INTEGER` | - | 1 If the plugin is internal else 0 |
| `active` | `INTEGER` | - | 1 If this plugin is active else 0 |

#### `osquery_schedule`
Information about the current queries that are scheduled in osquery. (**Scope**: Cross-platform (`utility/osquery_schedule.table`: `linux, macos, windows`) | **Attributes**: `utility=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `name` | `TEXT` | - | The given name for this query |
| `query` | `TEXT` | - | The exact query to run |
| `interval` | `INTEGER` | - | The interval in seconds to run this query, not an exact interval |
| `executions` | `BIGINT` | - | Number of times the query was executed |
| `last_executed` | `BIGINT` | - | UNIX time stamp in seconds of the last completed execution |
| `denylisted` | `INTEGER` | alias: `blacklisted` | 1 if the query is denylisted else 0 |
| `output_size` | `BIGINT` | - | Cumulative total number of bytes generated by the resultant rows of the query |
| `wall_time` | `BIGINT` | - | Total wall time in seconds spent executing (deprecated), hidden=True |
| `wall_time_ms` | `BIGINT` | - | Total wall time in milliseconds spent executing |
| `last_wall_time_ms` | `BIGINT` | - | Wall time in milliseconds of the latest execution |
| `user_time` | `BIGINT` | - | Total user time in milliseconds spent executing |
| `last_user_time` | `BIGINT` | - | User time in milliseconds of the latest execution |
| `system_time` | `BIGINT` | - | Total system time in milliseconds spent executing |
| `last_system_time` | `BIGINT` | - | System time in milliseconds of the latest execution |
| `average_memory` | `BIGINT` | - | Average of the bytes of resident memory left allocated after collecting results |
| `last_memory` | `BIGINT` | - | Resident memory in bytes left allocated after collecting results of the latest execution |

#### `time`
Track current date and time in UTC. (**Scope**: Cross-platform (`utility/time.table`: `linux, macos, windows`) | **Attributes**: `utility=True`)

| Column | Type | Flags | Description |
|---|---|---|---|
| `weekday` | `TEXT` | - | Current weekday in UTC |
| `year` | `INTEGER` | - | Current year in UTC |
| `month` | `INTEGER` | - | Current month in UTC |
| `day` | `INTEGER` | - | Current day in UTC |
| `hour` | `INTEGER` | - | Current hour in UTC |
| `minutes` | `INTEGER` | - | Current minutes in UTC |
| `seconds` | `INTEGER` | - | Current seconds in UTC |
| `timezone` | `TEXT` | - | Timezone for reported time (hardcoded to UTC) |
| `local_timezone` | `TEXT` | - | Current local timezone in of the system |
| `unix_time` | `INTEGER` | - | Current UNIX time in UTC |
| `timestamp` | `TEXT` | - | Current timestamp (log format) in UTC |
| `datetime` | `TEXT` | alias: `date_time` | Current date and time (ISO format) in UTC |
| `iso_8601` | `TEXT` | - | Current time (ISO format) in UTC |
| `win_timestamp` | `BIGINT` | `WINDOWS-EXT` | Timestamp value in 100 nanosecond units |
