---
name: darwin
description: >
  Complete macOS (darwin) osquery table catalog, schemas, required WHERE constraints,
  and platform-specific diagnostic guidelines. Activate this skill whenever diagnosing
  macOS (darwin) systems with osqueryi to select valid Darwin tables and write accurate SQL queries.
license: Apache-2.0
---

# macOS (`darwin`) osquery Diagnostic Reference

> *Table schemas and descriptions adapted from [osquery](https://github.com/osquery/osquery) specifications (licensed under Apache-2.0).*

This skill provides the complete, authoritative catalog of all **187 `darwin` osquery tables** (derived from the official osquery `specs/`, `specs/posix/`, `specs/darwin/`, `specs/macwin/`, `specs/sleuthkit/`, and `specs/utility/` specifications, and cross-verified against `osqueryi` on macOS).

---

## ⚠️ CRITICAL MACOS (`darwin`) PLATFORM GOTCHAS

> [!CAUTION]
> **NEVER query Linux-only or Windows-only tables on `darwin`.** Doing so will fail with `no such table` or return empty/misleading data. Read the platform mappings below before writing any SQL query.

### 1. `memory_info` DOES NOT EXIST on `darwin`!
- **`memory_info` is a Linux-only table (`specs/linux/memory_info.table`).** It does **not** exist on macOS (`darwin`).
- **How to diagnose memory on macOS (`darwin`) instead:**
  1. **`system_info`**: Query `SELECT physical_memory FROM system_info;` to get total installed physical RAM in bytes.
  2. **`virtual_memory_info`**: Query `SELECT * FROM virtual_memory_info;` for Darwin Mach VM page counts (`free`, `active`, `inactive`, `speculative`, `wired`, `purgeable`, `file_backed`, `anonymous`, `compressor`, `compressed`, `decompressed`, `page_ins`, `page_outs`, `swap_ins`, `swap_outs`).
     - **Page Size Note**: Values in `virtual_memory_info` are **page counts**, not bytes! Multiply by the hardware page size from `SELECT current_value FROM system_controls WHERE name = 'hw.pagesize';` (typically `16384` bytes on Apple Silicon `arm64`, or `4096` bytes on Intel `x86_64`).
     - **One-Query RAM Summary on Darwin**:
       ```sql
       SELECT
         s.physical_memory AS total_ram_bytes,
         ROUND(s.physical_memory / 1073741824.0, 2) AS total_ram_gb,
         CAST(sc.current_value AS BIGINT) AS page_size_bytes,
         ROUND((v.free + v.speculative) * CAST(sc.current_value AS BIGINT) / 1073741824.0, 2) AS free_gb,
         ROUND(v.active * CAST(sc.current_value AS BIGINT) / 1073741824.0, 2) AS active_gb,
         ROUND(v.inactive * CAST(sc.current_value AS BIGINT) / 1073741824.0, 2) AS inactive_gb,
         ROUND(v.wired * CAST(sc.current_value AS BIGINT) / 1073741824.0, 2) AS wired_gb,
         ROUND(v.compressor * CAST(sc.current_value AS BIGINT) / 1073741824.0, 2) AS compressed_occupied_gb,
         v.swap_ins,
         v.swap_outs,
         v.page_ins,
         v.page_outs
       FROM system_info s
       CROSS JOIN virtual_memory_info v
       CROSS JOIN system_controls sc
       WHERE sc.name = 'hw.pagesize';
       ```
  3. **`processes`**: Query top memory-consuming processes using `resident_size` (RSS in bytes), `wired_size` (wired bytes), and `total_size` (virtual memory size in bytes):
     ```sql
     SELECT pid, name, ROUND(resident_size / 1048576.0, 2) AS rss_mb, ROUND(total_size / 1048576.0, 2) AS vms_mb, cmdline
     FROM processes
     ORDER BY resident_size DESC
     LIMIT 15;
     ```
  4. **`system_controls` (Swap usage)**: Query `SELECT name, field_name, current_value FROM system_controls WHERE name = 'vm.swapusage';` for swap stats.
  5. **`memory_devices` / `memory_arrays`**: Rely on SMBIOS/DMI tables, which are populated on Intel Macs (`x86_64`) but typically empty on Apple Silicon (`arm64`). On Apple Silicon, use `system_info`, `virtual_memory_info`, or `SELECT * FROM system_profiler WHERE data_type = 'SPHardwareDataType';`.

### 2. Cross-Platform Replacement Cheat Sheet (Linux/Windows vs. Darwin)

| Diagnostic Goal | ❌ Do NOT Use on Darwin | ✅ Use on Darwin (`macos`) Instead |
|---|---|---|
| **RAM & Swap Usage** | `memory_info`, `memory_map` | `virtual_memory_info`, `system_info`, `processes`, `system_controls` |
| **Services & Daemons** | `systemd_units`, `services` | `launchd`, `launchd_overrides`, `startup_items`, `crontab` |
| **Firewall Config** | `iptables`, `windows_firewall_rules` | `alf`, `alf_exceptions`, `alf_explicit_auths`, `sharing_preferences` |
| **Installed Apps & Packages** | `deb_packages`, `rpm_packages`, `programs` | `apps`, `homebrew_packages`, `package_receipts`, `package_install_history` |
| **Kernel Modules / Drivers** | `kernel_modules`, `drivers` | `kernel_extensions`, `system_extensions` |
| **System Logs & Events** | `syslog_events`, `windows_eventlog` | `unified_log`, `asl`, `crashes`, `kernel_panics` |
| **Security & Integrity** | `selinux_settings`, `apparmor_profiles` | `sip_config`, `gatekeeper`, `xprotect_entries`, `xprotect_meta`, `xprotect_reports`, `signature`, `sandboxes` |
| **Disk Encryption** | `bitlocker_info` | `disk_encryption` (FileVault status per block device) |
| **CPU Features (`cpuid`)** | `cpuid` on Apple Silicon (`arm64`) | `cpu_info`, `system_info`, `system_controls WHERE name LIKE 'hw.optional.%'` (`cpuid` is `x86_64` only) |

### 3. Tables Requiring `WHERE` Clause Constraints (`required=True`)

Many osquery tables perform on-demand filesystem, network, or API lookups and **require** one or more columns in the `WHERE` clause (`=` or `IN` or `LIKE` where supported). Querying these tables without their required constraint returns empty results with a warning (`Table <name> was queried without a required column in the WHERE clause`).

| Table Name | Required `WHERE` Column(s) | Example / Usage Note |
|---|---|---|
| `curl` | `url` | `select url, round_trip_time, response_code from curl where url = 'https://github.com/osquery/osquery'` |
| `curl_certificate` | `hostname` | `select * from curl_certificate where hostname = 'osquery.io'` |
| `device_file` | `device`, `partition` | Similar to the file table, but use TSK and allow block address access. |
| `device_hash` | `device`, `partition`, `inode` | Similar to the hash table, but use TSK and allow block address access. |
| `device_partitions` | `device` | Use TSK to enumerate details about partitions on a disk device. |
| `docker_container_fs_changes` | `id` | `select * from docker_container_fs_changes where id = '1234567890abcdef'` |
| `docker_container_processes` | `id` | `select * from docker_container_processes where id = '1234567890abcdef'` |
| `docker_container_stats` | `id` | `select * from docker_container_stats where id = 'de8cfdc74c850967'` |
| `extended_attributes` | `path`, `directory` | Returns the extended attributes for files (similar to Windows ADS). |
| `file` | `path`, `directory` | `select * from file where path = '/etc/passwd'` |
| `hash` | `path`, `directory` | `select * from hash where path = '/etc/passwd'` |
| `magic` | `path` | Magic number recognition library table. |
| `mdfind` | `query` | `select * from mdfind where query = 'kMDItemDisplayName == "rook.stl"';` |
| `mdls` | `path` | `select * from mdls where path = '/Users/testuser/Desktop/testfile';` |
| `package_bom` | `path` | `select * from package_bom where path = '/var/db/receipts/com.apple.pkg.MobileDevice.bom'` |
| `plist` | `path` | `select * from plist where path = '/Library/Preferences/loginwindow.plist'` |
| `signature` | `path` | `SELECT * FROM signature WHERE path = '/bin/ls'` |
| `system_profiler` | `data_type` | `SELECT * FROM system_profiler WHERE data_type = 'SPUSBDataType';` |
| `yara_file` | `path` | `select * from yara_file where path = '/etc/passwd' and sigfile = '/etc/osquery/yara/test.yara'` |
| `yara_process` | `pid` | `select * from yara_process where pid = 1234 and sigfile = '/etc/osquery/yara/test.yara'` |

> [!TIP]
> **Other High-Volume Tables to Always Filter in `WHERE`:**
> - `unified_log`: Always filter with `predicate` and/or `max_rows` (hidden columns), e.g., `SELECT timestamp, process, message FROM unified_log WHERE predicate = 'process == "kernel"' AND max_rows = 100;`.
> - `system_profiler`: Always specify `WHERE data_type = '...'` (required column), e.g. `SPHardwareDataType`, `SPSoftwareDataType`, `SPDisplaysDataType`, `SPStorageDataType`, `SPPowerDataType`, `SPNVMeDataType`, `SPUSBDataType`.
> - `keychain_items` / `keychain_acls`: Can be slow across all keychains; filter by `WHERE path = '...'` or `type = '...'` when possible.
> - `process_open_files` / `process_memory_map`: Filter by `WHERE pid = ...` whenever inspecting a specific process to avoid scanning all system processes.

---

## 📂 Quick Diagnostic Category Index (All 187 Darwin Tables)

- **1. System & Hardware** (39 tables): `system_info`, `os_version`, `uptime`, `kernel_info`, `platform_info`, `cpu_info`, `cpuid`, `battery`, `fan_speed_sensors`, `temperature_sensors`, `power_sensors`, `smc_keys`, `connected_displays`, `usb_devices`, `pci_devices`, `iokit_devicetree`, `iokit_registry`, `ibridge_info`, `nvram`, `system_profiler`*, `system_controls`, `acpi_tables`, `smbios_tables`, `oem_strings`, `device_firmware`, `time`, `hardware_events`, `azure_instance_metadata`, `azure_instance_tags`, `ec2_instance_metadata`, `ec2_instance_tags`, `ycloud_instance_metadata`, `osquery_info`, `osquery_flags`, `osquery_registry`, `osquery_extensions`, `osquery_packs`, `osquery_schedule`, `osquery_events`
- **2. Memory & Performance** (10 tables): `virtual_memory_info`, `load_average`, `cpu_time`, `memory_devices`, `memory_arrays`, `memory_array_mapped_addresses`, `memory_device_mapped_addresses`, `memory_error_info`, `ulimit_info`, `prometheus_metrics`
- **3. Processes, Services & Launchd** (18 tables): `processes`, `process_envs`, `process_memory_map`, `process_open_files`, `process_open_sockets`, `process_events`, `es_process_events`, `es_process_file_events`, `running_apps`, `launchd`, `launchd_overrides`, `startup_items`, `crontab`, `event_taps`, `kernel_extensions`, `system_extensions`, `carbon_black_info`, `yara_process`*
- **4. Network & Ports** (21 tables): `listening_ports`, `interface_addresses`, `interface_details`, `interface_ipv6`, `routes`, `arp_cache`, `dns_resolvers`, `etc_hosts`, `etc_protocols`, `etc_services`, `wifi_status`, `wifi_networks`, `wifi_survey`, `curl`*, `curl_certificate`*, `socket_events`, `sharing_preferences`, `shared_folders`, `nfs_shares`, `cups_destinations`, `cups_jobs`
- **5. Filesystem, Disk & Spotlight** (22 tables): `mounts`, `block_devices`, `disk_encryption`, `disk_events`, `file`*, `file_events`, `hash`*, `extended_attributes`*, `mdfind`*, `mdls`*, `plist`*, `magic`*, `quicklook_cache`, `time_machine_backups`, `time_machine_destinations`, `augeas`, `carves`, `device_file`*, `device_hash`*, `device_partitions`*, `yara_file`*, `yara_events`
- **6. Users, Security, SIP & Keychain** (39 tables): `users`, `groups`, `user_groups`, `logged_in_users`, `last`, `user_events`, `user_interaction_events`, `shell_history`, `sudoers`, `suid_bin`, `ssh_configs`, `user_ssh_keys`, `authorized_keys`, `known_hosts`, `account_policy_data`, `password_policy`, `ad_config`, `authorizations`, `authorization_mechanisms`, `sip_config`, `gatekeeper`, `gatekeeper_approved_apps`, `alf`, `alf_exceptions`, `alf_explicit_auths`, `xprotect_entries`, `xprotect_meta`, `xprotect_reports`, `keychain_items`, `keychain_acls`, `certificates`, `certificate_trust_settings`, `signature`*, `sandboxes`, `screenlock`, `secureboot`, `location_services`, `managed_policies`, `preferences`
- **7. Logs & Crashes** (4 tables): `unified_log`, `asl`, `crashes`, `kernel_panics`
- **8. Packages, Homebrew, Apps & Containers** (34 tables): `apps`, `app_schemes`, `homebrew_packages`, `package_receipts`, `package_install_history`, `package_bom`*, `browser_plugins`, `chrome_extensions`, `chrome_extension_content_scripts`, `firefox_addons`, `safari_extensions`, `vscode_extensions`, `jetbrains_plugins`, `python_packages`, `npm_packages`, `docker_info`, `docker_version`, `docker_containers`, `docker_container_processes`*, `docker_container_stats`*, `docker_container_ports`, `docker_container_mounts`, `docker_container_networks`, `docker_container_envs`, `docker_container_labels`, `docker_container_fs_changes`*, `docker_images`, `docker_image_layers`, `docker_image_history`, `docker_image_labels`, `docker_networks`, `docker_network_labels`, `docker_volumes`, `docker_volume_labels`

*(Tables marked with `*` require a `WHERE` clause constraint.)*

---

## 📖 Complete Darwin Table Schemas (Categorized)

Below is the complete schema definition for all 187 tables available on `darwin`, grouped by diagnostic category.
Column flags:
- **`REQUIRED`**: Must be provided in the `WHERE` clause (for tables with multiple `REQUIRED` columns such as `file`, `hash`, or `extended_attributes`, supplying either `path` or `directory` satisfies the constraint).
- **`INDEXED`**: Fast key lookup in `WHERE` or `JOIN`.
- **`ADDITIONAL`**: Optional filter parameter that unlocks extra data or changes query scope when specified in `WHERE`.
- **`HIDDEN`**: Omitted from `SELECT *` and `PRAGMA table_info`, but selectable explicitly (`SELECT col_name ...`) and usable in `WHERE` (e.g., `unified_log.predicate`, `unified_log.max_rows`).
- **`DARWIN`**: Extended schema column specifically available on macOS/POSIX.

## 1. System & Hardware
Core operating system identification, hardware inventory, Apple Silicon / Intel CPU & sensor telemetry, IOKit registry, NVRAM, power/battery, and osquery internal metadata.

### `system_info` (`system_info.table`)
System information for identification.
- `hostname` (TEXT): Network hostname including domain
- `uuid` (TEXT): Unique ID provided by the system
- `cpu_type` (TEXT): CPU type
- `cpu_subtype` (TEXT): CPU subtype
- `cpu_brand` (TEXT): CPU brand string, contains vendor and model
- `cpu_physical_cores` (INTEGER): Number of physical CPU cores in to the system
- `cpu_logical_cores` (INTEGER): Number of logical CPU cores available to the system
- `cpu_sockets` (INTEGER): Number of processor sockets in the system
- `cpu_microcode` (TEXT): Microcode version
- `physical_memory` (BIGINT): Total physical memory in bytes
- `hardware_vendor` (TEXT): Hardware vendor
- `hardware_model` (TEXT): Hardware model
- `hardware_version` (TEXT): Hardware version
- `hardware_serial` (TEXT): Device serial number
- `board_vendor` (TEXT): Board vendor
- `board_model` (TEXT): Board model
- `board_version` (TEXT): Board version
- `board_serial` (TEXT): Board serial number
- `computer_name` (TEXT): Friendly computer name (optional)
- `local_hostname` (TEXT): Local hostname (optional)

### `os_version` (`os_version.table`)
A single row containing the operating system name and version.
- `name` (TEXT): Distribution or product name
- `version` (TEXT): Pretty, suitable for presentation, OS version
- `major` (INTEGER): Major release version
- `minor` (INTEGER): Minor release version
- `patch` (INTEGER): Optional patch release
- `build` (TEXT): Optional build-specific or variant string
- `platform` (TEXT): OS Platform or ID
- `platform_like` (TEXT): Closely related platforms
- `codename` (TEXT): OS version codename
- `arch` (TEXT): OS Architecture
- `extra` (TEXT, DARWIN): Optional extra release specification

### `uptime` (`uptime.table`)
Track time passed since last boot. Some systems track this as calendar time, some as runtime.
- `days` (INTEGER): Days of uptime
- `hours` (INTEGER): Hours of uptime
- `minutes` (INTEGER): Minutes of uptime
- `seconds` (INTEGER): Seconds of uptime
- `total_seconds` (BIGINT): Total uptime seconds

### `kernel_info` (`kernel_info.table`)
Basic active kernel information.
- `version` (TEXT): Kernel version
- `arguments` (TEXT): Kernel arguments
- `path` (TEXT): Kernel path
- `device` (TEXT): Kernel device identifier

### `platform_info` (`platform_info.table`)
Information about EFI/UEFI/ROM and platform/boot.
- `vendor` (TEXT): Platform code vendor
- `version` (TEXT): Platform code version
- `date` (TEXT): Self-reported platform code update date
- `revision` (TEXT): BIOS major and minor revision
- `extra` (TEXT): Platform-specific additional information
- `firmware_type` (TEXT): The type of firmware (uefi, bios, iboot, openfirmware, unknown).
- `address` (TEXT, DARWIN): Relative address of firmware mapping
- `size` (TEXT, DARWIN): Size in bytes of firmware
- `volume_size` (INTEGER, DARWIN): (Optional) size of firmware volume

### `cpu_info` (`cpu_info.table`)
Retrieve cpu hardware info of the machine.
- `device_id` (TEXT): The DeviceID of the CPU.
- `model` (TEXT): The model of the CPU.
- `manufacturer` (TEXT): The manufacturer of the CPU.
- `processor_type` (TEXT): The processor type, such as Central, Math, or Video.
- `cpu_status` (INTEGER): The current operating status of the CPU.
- `number_of_cores` (TEXT): The number of cores of the CPU.
- `logical_processors` (INTEGER): The number of logical processors of the CPU.
- `address_width` (TEXT): The width of the CPU address bus.
- `current_clock_speed` (INTEGER): The current frequency of the CPU.
- `max_clock_speed` (INTEGER): The maximum possible frequency of the CPU.
- `socket_designation` (TEXT): The assigned socket on the board for the given CPU.
- `number_of_efficiency_cores` (INTEGER, DARWIN): The number of efficiency cores of the CPU. Only available on Apple Silicon
- `number_of_performance_cores` (INTEGER, DARWIN): The number of performance cores of the CPU. Only available on Apple Silicon

### `cpuid` (`cpuid.table` | arch: `x86_64` only)
Useful CPU features from the cpuid ASM call.
- `feature` (TEXT): Present feature flags
- `value` (TEXT): Bit value or string
- `output_register` (TEXT): Register used to for feature value
- `output_bit` (INTEGER): Bit in register value for feature value
- `input_eax` (TEXT): Value of EAX used

### `battery` (`macwin/battery.table`)
Provides information about the internal battery of a laptop. Note: On Windows, columns with Ah or mAh units assume that the battery is 12V.
- `manufacturer` (TEXT): The battery manufacturer's name
- `model` (TEXT): The battery's model number
- `serial_number` (TEXT): The battery's serial number
- `cycle_count` (INTEGER): The number of charge/discharge cycles
- `state` (TEXT): One of the following: "AC Power" indicates the battery is connected to an external power source, "Battery Power" indicates that the battery is drawing internal power, "Off Line" indicates the battery is off-line or no longer connected
- `charging` (INTEGER): 1 if the battery is currently being charged by a power source. 0 otherwise
- `charged` (INTEGER): 1 if the battery is currently completely charged. 0 otherwise
- `designed_capacity` (INTEGER): The battery's designed capacity in mAh
- `max_capacity` (INTEGER): The battery's actual capacity when it is fully charged in mAh
- `current_capacity` (INTEGER): The battery's current capacity (level of charge) in mAh
- `percent_remaining` (INTEGER): The percentage of battery remaining before it is drained
- `amperage` (INTEGER): The current amperage in/out of the battery in mA (positive means charging, negative means discharging)
- `voltage` (INTEGER): The battery's current voltage in mV
- `minutes_until_empty` (INTEGER): The number of minutes until the battery is fully depleted. This value is -1 if this time is still being calculated
- `minutes_to_full_charge` (INTEGER): The number of minutes until the battery is fully charged. This value is -1 if this time is still being calculated. On Windows this is calculated from the charge rate and capacity and may not agree with the number reported in "Power & Battery"
- `health` (TEXT, DARWIN): One of the following: "Good" describes a well-performing battery, "Fair" describes a functional battery with limited capacity, or "Poor" describes a battery that's not capable of providing power
- `condition` (TEXT, DARWIN): One of the following: "Normal" indicates the condition of the battery is within normal tolerances, "Service Needed" indicates that the battery should be checked out by a licensed Mac repair service, "Permanent Failure" indicates the battery needs replacement
- `manufacture_date` (INTEGER, DARWIN): The date the battery was manufactured UNIX Epoch

### `fan_speed_sensors` (`darwin/fan_speed_sensors.table`)
Fan speeds.
- `fan` (TEXT): Fan number
- `name` (TEXT): Fan name
- `actual` (INTEGER): Actual speed
- `min` (INTEGER): Minimum speed
- `max` (INTEGER): Maximum speed
- `target` (INTEGER): Target speed

### `temperature_sensors` (`darwin/temperature_sensors.table`)
Machine's temperature sensors.
- `key` (TEXT, INDEXED): The SMC key on macOS
- `name` (TEXT): Name of temperature source
- `celsius` (DOUBLE): Temperature in Celsius
- `fahrenheit` (DOUBLE): Temperature in Fahrenheit

### `power_sensors` (`darwin/power_sensors.table`)
Machine power (currents, voltages, wattages, etc) sensors.
- `key` (TEXT, INDEXED): The SMC key on macOS
- `category` (TEXT): The sensor category: currents, voltage, wattage
- `name` (TEXT): Name of power source
- `value` (TEXT): Power in Watts
- *Example*: `select * from power_sensors where category = 'voltage';`

### `smc_keys` (`darwin/smc_keys.table`)
Apple's system management controller keys.
- `key` (TEXT, INDEXED, ADDITIONAL): 4-character key
- `type` (TEXT): SMC-reported type literal type
- `size` (INTEGER): Reported size of data in bytes
- `value` (TEXT): A type-encoded representation of the key value
- `hidden` (INTEGER): 1 if this key is normally hidden, otherwise 0
- *Example*: `select * from smc_keys where key = 'MOJO';`

### `connected_displays` (`darwin/connected_displays.table`)
Provides information about the connected displays of the machine.
- `name` (TEXT): The name of the display.
- `product_id` (TEXT): The product ID of the display.
- `serial_number` (TEXT): The serial number of the display. (may not be unique)
- `vendor_id` (TEXT): The vendor ID of the display.
- `manufactured_week` (INTEGER): The manufacture week of the display. This field is 0 if not supported
- `manufactured_year` (INTEGER): The manufacture year of the display. This field is 0 if not supported
- `display_id` (TEXT): The display ID.
- `pixels` (TEXT): The number of pixels of the display.
- `resolution` (TEXT): The resolution of the display.
- `ambient_brightness_enabled` (TEXT): The ambient brightness setting associated with the display. This will be 1 if enabled and is 0 if disabled or not supported.
- `connection_type` (TEXT): The connection type associated with the display.
- `display_type` (TEXT): The type of display.
- `main` (INTEGER): If the display is the main display.
- `mirror` (INTEGER): If the display is mirrored or not. This field is 1 if mirrored and 0 if not mirrored.
- `online` (INTEGER): The online status of the display. This field is 1 if the display is online and 0 if it is offline.
- `rotation` (TEXT): The rotation of the display (0, 90, 180, or 270 degrees). This field is -1 if display rotation is not supported.

### `usb_devices` (`posix/usb_devices.table`)
USB devices that are actively plugged into the host system.
- `usb_address` (INTEGER): USB Device used address
- `usb_port` (INTEGER): USB Device used port
- `vendor` (TEXT): USB Device vendor string
- `vendor_id` (TEXT): Hex encoded USB Device vendor identifier
- `version` (TEXT): USB Device version number
- `model` (TEXT): USB Device model string
- `model_id` (TEXT): Hex encoded USB Device model identifier
- `serial` (TEXT): USB Device serial connection
- `class` (TEXT): USB Device class
- `subclass` (TEXT): USB Device subclass
- `protocol` (TEXT): USB Device protocol
- `removable` (INTEGER): 1 If USB device is removable else 0

### `pci_devices` (`posix/pci_devices.table`)
PCI devices active on the host system.
- `pci_slot` (TEXT): PCI Device used slot
- `pci_class` (TEXT): PCI Device class
- `driver` (TEXT): PCI Device used driver
- `vendor` (TEXT): PCI Device vendor
- `vendor_id` (TEXT): Hex encoded PCI Device vendor identifier
- `model` (TEXT): PCI Device model
- `model_id` (TEXT): Hex encoded PCI Device model identifier

### `iokit_devicetree` (`darwin/iokit_devicetree.table`)
The IOKit registry matching the DeviceTree plane.
- `name` (TEXT): Device node name
- `class` (TEXT): Best matching device class (most-specific category)
- `id` (BIGINT): IOKit internal registry ID
- `parent` (BIGINT): Parent device registry ID
- `device_path` (TEXT): Device tree path
- `service` (INTEGER): 1 if the device conforms to IOService else 0
- `busy_state` (INTEGER): 1 if the device is in a busy state else 0
- `retain_count` (INTEGER): The device reference count
- `depth` (INTEGER): Device nested depth

### `iokit_registry` (`darwin/iokit_registry.table`)
The full IOKit registry without selecting a plane.
- `name` (TEXT): Default name of the node
- `class` (TEXT): Best matching device class (most-specific category)
- `id` (BIGINT): IOKit internal registry ID
- `parent` (BIGINT): Parent registry ID
- `busy_state` (INTEGER): 1 if the node is in a busy state else 0
- `retain_count` (INTEGER): The node reference count
- `depth` (INTEGER): Node nested depth

### `ibridge_info` (`darwin/ibridge_info.table`)
Information about the Apple iBridge hardware controller.
- `boot_uuid` (TEXT): Boot UUID of the iBridge controller
- `coprocessor_version` (TEXT): The manufacturer and chip version
- `firmware_version` (TEXT): The build version of the firmware
- `unique_chip_id` (TEXT): Unique id of the iBridge controller

### `nvram` (`darwin/nvram.table`)
Apple NVRAM variable listing.
- `name` (TEXT, INDEXED, ADDITIONAL): Variable name
- `type` (TEXT): Data type (CFData, CFString, etc)
- `value` (TEXT): Raw variable data

### `system_profiler` (`darwin/system_profiler.table`)
Query system_profiler data types and return the full result as JSON. Returns only the data types specified in the constraints. See available data types with `system_profiler -listDataTypes`.
- **Required `WHERE` constraint**: `data_type`
- `data_type` (TEXT, REQUIRED): The system profiler data type (e.g., SPHardwareDataType)
- `value` (TEXT): A JSON representation of the full result dictionary for the data type
- *Example*: `SELECT * FROM system_profiler WHERE data_type = 'SPUSBDataType'; SELECT JSON_EXTRACT(value, '$[0].platform_UUID') AS hardware_uuid FROM system_profiler WHERE data_type = 'SPHardwareDataType';`

### `system_controls` (`posix/system_controls.table`)
sysctl names, values, and settings information.
- `name` (TEXT, INDEXED): Full sysctl MIB name
- `oid` (TEXT, ADDITIONAL): Control MIB
- `subsystem` (TEXT, ADDITIONAL): Subsystem ID, control type
- `current_value` (TEXT): Value of setting
- `config_value` (TEXT): The MIB value set in /etc/sysctl.conf
- `type` (TEXT): Data type
- `field_name` (TEXT, DARWIN): Specific attribute of opaque type

### `acpi_tables` (`posix/acpi_tables.table`)
Firmware ACPI functional table common metadata and content.
- `name` (TEXT): ACPI table name
- `size` (INTEGER): Size of compiled table data
- `md5` (TEXT): MD5 hash of table content

### `smbios_tables` (`posix/smbios_tables.table`)
BIOS (DMI) structure common details and content.
- `number` (INTEGER): Table entry number
- `type` (INTEGER): Table entry type
- `description` (TEXT): Table entry description
- `handle` (INTEGER): Table entry handle
- `header_size` (INTEGER): Header size in bytes
- `size` (INTEGER): Table entry size in bytes
- `md5` (TEXT): MD5 hash of table entry

### `oem_strings` (`posix/oem_strings.table`)
OEM defined strings retrieved from SMBIOS.
- `handle` (TEXT): Handle, or instance number, associated with the Type 11 structure
- `number` (INTEGER): The string index of the structure
- `value` (TEXT): The value of the OEM string

### `device_firmware` (`darwin/device_firmware.table`)
A best-effort list of discovered firmware versions.
- `type` (TEXT): Type of device
- `device` (TEXT, INDEXED): The device name
- `version` (TEXT): Firmware version

### `time` (`utility/time.table`)
Track current date and time in UTC.
- `weekday` (TEXT): Current weekday in UTC
- `year` (INTEGER): Current year in UTC
- `month` (INTEGER): Current month in UTC
- `day` (INTEGER): Current day in UTC
- `hour` (INTEGER): Current hour in UTC
- `minutes` (INTEGER): Current minutes in UTC
- `seconds` (INTEGER): Current seconds in UTC
- `timezone` (TEXT): Timezone for reported time (hardcoded to UTC)
- `local_timezone` (TEXT): Current local timezone in of the system
- `unix_time` (INTEGER): Current UNIX time in UTC
- `timestamp` (TEXT): Current timestamp (log format) in UTC
- `datetime` (TEXT, alias:date_time): Current date and time (ISO format) in UTC
- `iso_8601` (TEXT): Current time (ISO format) in UTC

### `hardware_events` (`posix/hardware_events.table` | event subscriber)
Hardware (PCI/USB/HID) events from UDEV or IOKit.
- `action` (TEXT): Remove, insert, change properties, etc
- `path` (TEXT): Local device path assigned (optional)
- `type` (TEXT): Type of hardware and hardware event
- `driver` (TEXT): Driver claiming the device
- `vendor` (TEXT): Hardware device vendor
- `vendor_id` (TEXT): Hex encoded Hardware vendor identifier
- `model` (TEXT): Hardware device model
- `model_id` (TEXT): Hex encoded Hardware model identifier
- `serial` (TEXT): Device serial (optional)
- `revision` (TEXT): Device revision (optional)
- `time` (BIGINT, ADDITIONAL): Time of hardware event
- `eid` (TEXT, HIDDEN): Event ID

### `azure_instance_metadata` (`azure_instance_metadata.table`)
Azure instance metadata.
- `location` (TEXT): Azure Region the VM is running in
- `name` (TEXT): Name of the VM
- `offer` (TEXT): Offer information for the VM image (Azure image gallery VMs only)
- `publisher` (TEXT): Publisher of the VM image
- `sku` (TEXT): SKU for the VM image
- `version` (TEXT): Version of the VM image
- `os_type` (TEXT): Linux or Windows
- `platform_update_domain` (TEXT): Update domain the VM is running in
- `platform_fault_domain` (TEXT): Fault domain the VM is running in
- `vm_id` (TEXT, INDEXED): Unique identifier for the VM
- `vm_size` (TEXT): VM size
- `subscription_id` (TEXT): Azure subscription for the VM
- `resource_group_name` (TEXT): Resource group for the VM
- `placement_group_id` (TEXT): Placement group for the VM scale set
- `vm_scale_set_name` (TEXT): VM scale set name
- `zone` (TEXT): Availability zone of the VM
- *Example*: `select * from azure_instance_metadata;`

### `azure_instance_tags` (`azure_instance_tags.table`)
Azure instance tags.
- `vm_id` (TEXT): Unique identifier for the VM
- `key` (TEXT): The tag key
- `value` (TEXT): The tag value
- *Example*: `select * from azure_instance_tags;`

### `ec2_instance_metadata` (`ec2_instance_metadata.table`)
EC2 instance metadata.
- `instance_id` (TEXT): EC2 instance ID
- `instance_type` (TEXT): EC2 instance type
- `architecture` (TEXT): Hardware architecture of this EC2 instance
- `region` (TEXT): AWS region in which this instance launched
- `availability_zone` (TEXT): Availability zone in which this instance launched
- `local_hostname` (TEXT): Private IPv4 DNS hostname of the first interface of this instance
- `local_ipv4` (TEXT): Private IPv4 address of the first interface of this instance
- `mac` (TEXT): MAC address for the first network interface of this EC2 instance
- `security_groups` (TEXT): Comma separated list of security group names
- `iam_arn` (TEXT): If there is an IAM role associated with the instance, contains instance profile ARN
- `ami_id` (TEXT): AMI ID used to launch this EC2 instance
- `reservation_id` (TEXT): ID of the reservation
- `account_id` (TEXT): AWS account ID which owns this EC2 instance
- `ssh_public_key` (TEXT): SSH public key. Only available if supplied at instance launch time
- *Example*: `select * from ec2_instance_metadata;`

### `ec2_instance_tags` (`ec2_instance_tags.table`)
EC2 instance tag key value pairs.
- `instance_id` (TEXT): EC2 instance ID
- `key` (TEXT): Tag key
- `value` (TEXT): Tag value
- *Example*: `select * from ec2_instance_tags;`

### `ycloud_instance_metadata` (`ycloud_instance_metadata.table`)
Yandex.Cloud instance metadata.
- `instance_id` (TEXT, INDEXED): Unique identifier for the VM
- `folder_id` (TEXT): Folder identifier for the VM
- `cloud_id` (TEXT): Cloud identifier for the VM
- `name` (TEXT): Name of the VM
- `description` (TEXT): Description of the VM
- `hostname` (TEXT): Hostname of the VM
- `zone` (TEXT): Availability zone of the VM
- `ssh_public_key` (TEXT): SSH public key. Only available if supplied at instance launch time
- `serial_port_enabled` (TEXT): Indicates if serial port is enabled for the VM
- `metadata_endpoint` (TEXT, INDEXED): Endpoint used to fetch VM metadata
- *Example*: `select * from ycloud_instance_metadata; select * from ycloud_instance_metadata where metadata_endpoint="http://169.254.169.254";`

### `osquery_info` (`utility/osquery_info.table`)
Top level information about the running version of osquery.
- `pid` (INTEGER): Process (or thread/handle) ID
- `uuid` (TEXT): Unique ID provided by the system
- `instance_id` (TEXT): Unique, long-lived ID per instance of osquery
- `version` (TEXT): osquery toolkit version
- `config_hash` (TEXT): Hash of the working configuration state
- `config_valid` (INTEGER): 1 if the config was loaded and considered valid, else 0
- `extensions` (TEXT): osquery extensions status
- `build_platform` (TEXT): osquery toolkit build platform
- `build_distro` (TEXT): osquery toolkit platform distribution name (os version)
- `start_time` (INTEGER): UNIX time in seconds when the process started
- `watcher` (INTEGER): Process (or thread/handle) ID of optional watcher process
- `platform_mask` (INTEGER): The osquery platform bitmask

### `osquery_flags` (`utility/osquery_flags.table`)
Configurable flags that modify osquery's behavior.
- `name` (TEXT): Flag name
- `type` (TEXT): Flag type
- `description` (TEXT): Flag description
- `default_value` (TEXT): Flag default value
- `value` (TEXT): Flag value
- `shell_only` (INTEGER): Is the flag shell only?

### `osquery_registry` (`utility/osquery_registry.table`)
List the osquery registry plugins.
- `registry` (TEXT): Name of the osquery registry
- `name` (TEXT): Name of the plugin item
- `owner_uuid` (INTEGER): Extension route UUID (0 for core)
- `internal` (INTEGER): 1 If the plugin is internal else 0
- `active` (INTEGER): 1 If this plugin is active else 0

### `osquery_extensions` (`utility/osquery_extensions.table`)
List of active osquery extensions.
- `uuid` (BIGINT): The transient ID assigned for communication
- `name` (TEXT): Extension's name
- `version` (TEXT): Extension's version
- `sdk_version` (TEXT): osquery SDK version used to build the extension
- `path` (TEXT): Path of the extension's Thrift connection or library path
- `type` (TEXT): SDK extension type: core, extension, or module

### `osquery_packs` (`utility/osquery_packs.table`)
Information about the current query packs that are loaded in osquery.
- `name` (TEXT): The given name for this query pack
- `platform` (TEXT): Platforms this query is supported on
- `version` (TEXT): Minimum osquery version that this query will run on
- `shard` (INTEGER): Shard restriction limit, 1-100, 0 meaning no restriction
- `discovery_cache_hits` (INTEGER): The number of times that the discovery query used cached values since the last time the config was reloaded
- `discovery_executions` (INTEGER): The number of times that the discovery queries have been executed since the last time the config was reloaded
- `active` (INTEGER): Whether this pack is active (the version, platform and discovery queries match) yes=1, no=0.

### `osquery_schedule` (`utility/osquery_schedule.table`)
Information about the current queries that are scheduled in osquery.
- `name` (TEXT): The given name for this query
- `query` (TEXT): The exact query to run
- `interval` (INTEGER): The interval in seconds to run this query, not an exact interval
- `executions` (BIGINT): Number of times the query was executed
- `last_executed` (BIGINT): UNIX time stamp in seconds of the last completed execution
- `denylisted` (INTEGER, alias:blacklisted): 1 if the query is denylisted else 0
- `output_size` (BIGINT): Cumulative total number of bytes generated by the resultant rows of the query
- `wall_time` (BIGINT): Total wall time in seconds spent executing (deprecated), hidden=True
- `wall_time_ms` (BIGINT): Total wall time in milliseconds spent executing
- `last_wall_time_ms` (BIGINT): Wall time in milliseconds of the latest execution
- `user_time` (BIGINT): Total user time in milliseconds spent executing
- `last_user_time` (BIGINT): User time in milliseconds of the latest execution
- `system_time` (BIGINT): Total system time in milliseconds spent executing
- `last_system_time` (BIGINT): System time in milliseconds of the latest execution
- `average_memory` (BIGINT): Average of the bytes of resident memory left allocated after collecting results
- `last_memory` (BIGINT): Resident memory in bytes left allocated after collecting results of the latest execution

### `osquery_events` (`utility/osquery_events.table`)
Information about the event publishers and subscribers.
- `name` (TEXT): Event publisher or subscriber name
- `publisher` (TEXT): Name of the associated publisher
- `type` (TEXT): Either publisher or subscriber
- `subscriptions` (INTEGER): Number of subscriptions the publisher received or subscriber used
- `events` (INTEGER): Number of events emitted or received since osquery started
- `refreshes` (INTEGER): Publisher only: number of runloop restarts
- `active` (INTEGER): 1 if the publisher or subscriber is active else 0

## 2. Memory & Performance
Darwin virtual memory statistics, swap/compressor pressure, load averages, CPU time per core, resource limits, and SMBIOS memory hardware tables.

### `virtual_memory_info` (`darwin/virtual_memory_info.table`)
Darwin Virtual Memory statistics.
- `free` (BIGINT): Total number of free pages.
- `active` (BIGINT): Total number of active pages.
- `inactive` (BIGINT): Total number of inactive pages.
- `speculative` (BIGINT): Total number of speculative pages.
- `throttled` (BIGINT): Total number of throttled pages.
- `wired` (BIGINT): Total number of wired down pages.
- `purgeable` (BIGINT): Total number of purgeable pages.
- `faults` (BIGINT): Total number of calls to vm_faults.
- `copy` (BIGINT): Total number of copy-on-write pages.
- `zero_fill` (BIGINT): Total number of zero filled pages.
- `reactivated` (BIGINT): Total number of reactivated pages.
- `purged` (BIGINT): Total number of purged pages.
- `file_backed` (BIGINT): Total number of file backed pages.
- `anonymous` (BIGINT): Total number of anonymous pages.
- `uncompressed` (BIGINT): Total number of uncompressed pages.
- `compressor` (BIGINT): The number of pages used to store compressed VM pages.
- `decompressed` (BIGINT): The total number of pages that have been decompressed by the VM compressor.
- `compressed` (BIGINT): The total number of pages that have been compressed by the VM compressor.
- `page_ins` (BIGINT): The total number of requests for pages from a pager.
- `page_outs` (BIGINT): Total number of pages paged out.
- `swap_ins` (BIGINT): The total number of compressed pages that have been swapped out to disk.
- `swap_outs` (BIGINT): The total number of compressed pages that have been swapped back in from disk.
- *Example*: `select * from virtual_memory_info;`

### `load_average` (`posix/load_average.table`)
Displays information about the system wide load averages.
- `period` (TEXT): Period over which the average is calculated.
- `average` (TEXT): Load average over the specified period.
- *Example*: `select * from load_average;`

### `cpu_time` (`posix/cpu_time.table`)
Displays information from /proc/stat file about the time the cpu cores spent in different parts of the system.
- `core` (INTEGER): Name of the cpu (core)
- `user` (BIGINT): Time spent in user mode
- `nice` (BIGINT): Time spent in user mode with low priority (nice)
- `system` (BIGINT): Time spent in system mode
- `idle` (BIGINT): Time spent in the idle task
- `iowait` (BIGINT): Time spent waiting for I/O to complete
- `irq` (BIGINT): Time spent servicing interrupts
- `softirq` (BIGINT): Time spent servicing softirqs
- `steal` (BIGINT): Time spent in other operating systems when running in a virtualized environment
- `guest` (BIGINT): Time spent running a virtual CPU for a guest OS under the control of the Linux kernel
- `guest_nice` (BIGINT): Time spent running a niced guest

### `memory_devices` (`memory_devices.table`)
Physical memory device (type 17) information retrieved from SMBIOS.
- `handle` (TEXT): Handle, or instance number, associated with the structure in SMBIOS
- `array_handle` (TEXT): The memory array that the device is attached to
- `form_factor` (TEXT): Implementation form factor for this memory device
- `total_width` (INTEGER): Total width, in bits, of this memory device, including any check or error-correction bits
- `data_width` (INTEGER): Data width, in bits, of this memory device
- `size` (INTEGER): Size of memory device in Megabyte
- `set` (INTEGER): Identifies if memory device is one of a set of devices.  A value of 0 indicates no set affiliation.
- `device_locator` (TEXT): String number of the string that identifies the physically-labeled socket or board position where the memory device is located
- `bank_locator` (TEXT): String number of the string that identifies the physically-labeled bank where the memory device is located
- `memory_type` (TEXT): Type of memory used
- `memory_type_details` (TEXT): Additional details for memory device
- `max_speed` (INTEGER): Max speed of memory device in megatransfers per second (MT/s)
- `configured_clock_speed` (INTEGER): Configured speed of memory device in megatransfers per second (MT/s)
- `manufacturer` (TEXT): Manufacturer ID string
- `serial_number` (TEXT): Serial number of memory device
- `asset_tag` (TEXT): Manufacturer specific asset tag of memory device
- `part_number` (TEXT): Manufacturer specific serial number of memory device
- `min_voltage` (INTEGER): Minimum operating voltage of device in millivolts
- `max_voltage` (INTEGER): Maximum operating voltage of device in millivolts
- `configured_voltage` (INTEGER): Configured operating voltage of device in millivolts

### `memory_arrays` (`posix/memory_arrays.table`)
Data associated with collection of memory devices that operate to form a memory address.
- `handle` (TEXT): Handle, or instance number, associated with the array
- `location` (TEXT): Physical location of the memory array
- `use` (TEXT): Function for which the array is used
- `memory_error_correction` (TEXT): Primary hardware error correction or detection method supported
- `max_capacity` (INTEGER): Maximum capacity of array in gigabytes
- `memory_error_info_handle` (TEXT): Handle, or instance number, associated with any error that was detected for the array
- `number_memory_devices` (INTEGER): Number of memory devices on array

### `memory_array_mapped_addresses` (`posix/memory_array_mapped_addresses.table`)
Data associated for address mapping of physical memory arrays.
- `handle` (TEXT): Handle, or instance number, associated with the structure
- `memory_array_handle` (TEXT): Handle of the memory array associated with this structure
- `starting_address` (TEXT): Physical stating address, in kilobytes, of a range of memory mapped to physical memory array
- `ending_address` (TEXT): Physical ending address of last kilobyte of a range of memory mapped to physical memory array
- `partition_width` (INTEGER): Number of memory devices that form a single row of memory for the address partition of this structure

### `memory_device_mapped_addresses` (`posix/memory_device_mapped_addresses.table`)
Data associated for address mapping of physical memory devices.
- `handle` (TEXT): Handle, or instance number, associated with the structure
- `memory_device_handle` (TEXT): Handle of the memory device structure associated with this structure
- `memory_array_mapped_address_handle` (TEXT): Handle of the memory array mapped address to which this device range is mapped to
- `starting_address` (TEXT): Physical stating address, in kilobytes, of a range of memory mapped to physical memory array
- `ending_address` (TEXT): Physical ending address of last kilobyte of a range of memory mapped to physical memory array
- `partition_row_position` (INTEGER): Identifies the position of the referenced memory device in a row of the address partition
- `interleave_position` (INTEGER): The position of the device in a interleave, i.e. 0 indicates non-interleave, 1 indicates 1st interleave, 2 indicates 2nd interleave, etc.
- `interleave_data_depth` (INTEGER): The max number of consecutive rows from memory device that are accessed in a single interleave transfer; 0 indicates device is non-interleave

### `memory_error_info` (`posix/memory_error_info.table`)
Data associated with errors of a physical memory array.
- `handle` (TEXT): Handle, or instance number, associated with the structure
- `error_type` (TEXT): type of error associated with current error status for array or device
- `error_granularity` (TEXT): Granularity to which the error can be resolved
- `error_operation` (TEXT): Memory access operation that caused the error
- `vendor_syndrome` (TEXT): Vendor specific ECC syndrome or CRC data associated with the erroneous access
- `memory_array_error_address` (TEXT): 32 bit physical address of the error based on the addressing of the bus to which the memory array is connected
- `device_error_address` (TEXT): 32 bit physical address of the error relative to the start of the failing memory address, in bytes
- `error_resolution` (TEXT): Range, in bytes, within which this error can be determined, when an error address is given

### `ulimit_info` (`posix/ulimit_info.table`)
System resource usage limits.
- `type` (TEXT): System resource to be limited
- `soft_limit` (TEXT): Current limit value
- `hard_limit` (TEXT): Maximum limit value
- *Example*: `select * from ulimit_info;`

### `prometheus_metrics` (`posix/prometheus_metrics.table`)
Retrieve metrics from a Prometheus server.
- `target_name` (TEXT): Address of prometheus target
- `metric_name` (TEXT): Name of collected Prometheus metric
- `metric_value` (DOUBLE): Value of collected Prometheus metric
- `timestamp_ms` (BIGINT): Unix timestamp of collected data in MS

## 3. Processes, Services & Launchd
Running processes, memory maps, open file descriptors and sockets, macOS LaunchAgents/LaunchDaemons (`launchd`), login/startup items, cron jobs, Endpoint Security events, and kernel/system extensions.

### `processes` (`processes.table`)
All running processes on the host system.
- `pid` (BIGINT, INDEXED): Process (or thread) ID
- `name` (TEXT): The process path or shorthand argv[0]
- `path` (TEXT): Path to executed binary
- `cmdline` (TEXT): Complete argv
- `state` (TEXT): Process state
- `cwd` (TEXT): Process current working directory
- `root` (TEXT): Process virtual root directory
- `uid` (BIGINT): Unsigned user ID
- `gid` (BIGINT): Unsigned group ID
- `euid` (BIGINT): Unsigned effective user ID
- `egid` (BIGINT): Unsigned effective group ID
- `suid` (BIGINT): Unsigned saved user ID
- `sgid` (BIGINT): Unsigned saved group ID
- `on_disk` (INTEGER): The process path exists yes=1, no=0, unknown=-1
- `wired_size` (BIGINT): Bytes of unpageable memory used by process
- `resident_size` (BIGINT): Bytes of private memory used by process
- `total_size` (BIGINT): Total virtual memory size (Linux, Windows) or 'footprint' (macOS)
- `user_time` (BIGINT): CPU time in milliseconds spent in user space
- `system_time` (BIGINT): CPU time in milliseconds spent in kernel space
- `disk_bytes_read` (BIGINT): Bytes read from disk
- `disk_bytes_written` (BIGINT): Bytes written to disk
- `start_time` (BIGINT): Process start time in seconds since Epoch, in case of error -1
- `parent` (BIGINT): Process parent's PID
- `pgroup` (BIGINT): Process group
- `threads` (INTEGER): Number of threads used by process
- `nice` (INTEGER): Process nice level (-20 to 20, default 0)
- `upid` (BIGINT, DARWIN): A 64bit pid that is never reused. Returns -1 if we couldn't gather them from the system.
- `uppid` (BIGINT, DARWIN): The 64bit parent pid that is never reused. Returns -1 if we couldn't gather them from the system.
- `cpu_type` (INTEGER, DARWIN): Indicates the specific processor designed for installation.
- `cpu_subtype` (INTEGER, DARWIN): Indicates the specific processor on which an entry may be used.
- `translated` (INTEGER, DARWIN): Indicates whether the process is running under the Rosetta Translation Environment, yes=1, no=0, error=-1.
- *Example*: `select * from processes where pid = 1;`

### `process_envs` (`posix/process_envs.table`)
A key/value table of environment variables for each process.
- `pid` (INTEGER, INDEXED): Process (or thread) ID
- `key` (TEXT): Environment variable name
- `value` (TEXT): Environment variable value
- *Example*: `select * from process_envs where pid = 1;`

### `process_memory_map` (`process_memory_map.table`)
Process memory mapped files and pseudo device/regions.
- `pid` (INTEGER, INDEXED): Process (or thread) ID
- `start` (TEXT): Virtual start address (hex)
- `end` (TEXT): Virtual end address (hex)
- `permissions` (TEXT): r=read, w=write, x=execute, p=private (cow)
- `offset` (BIGINT): Offset into mapped path
- `device` (TEXT): MA:MI Major/minor device ID
- `inode` (INTEGER): Mapped path inode, 0 means uninitialized (BSS)
- `path` (TEXT): Path to mapped file or mapped type
- `pseudo` (INTEGER): 1 If path is a pseudo path, else 0
- *Example*: `select * from process_memory_map where pid = 1;`

### `process_open_files` (`posix/process_open_files.table`)
File descriptors for each process.
- `pid` (BIGINT, INDEXED): Process (or thread) ID
- `fd` (BIGINT): Process-specific file descriptor number
- `path` (TEXT): Filesystem path of descriptor
- *Example*: `select * from process_open_files where pid = 1;`

### `process_open_sockets` (`process_open_sockets.table`)
Processes which have open network sockets on the system.
- `pid` (INTEGER, ADDITIONAL): Process (or thread) ID
- `fd` (BIGINT): Socket file descriptor number
- `socket` (BIGINT): Socket handle or inode number
- `family` (INTEGER): Network protocol (IPv4, IPv6)
- `protocol` (INTEGER): Transport protocol (TCP/UDP)
- `local_address` (TEXT): Socket local address
- `remote_address` (TEXT): Socket remote address
- `local_port` (INTEGER): Socket local port
- `remote_port` (INTEGER): Socket remote port
- `path` (TEXT): For UNIX sockets (family=AF_UNIX), the domain path
- `state` (TEXT): TCP socket state
- *Example*: `select * from process_open_sockets where pid = 1;`

### `process_events` (`posix/process_events.table` | event subscriber)
Track time/action process executions.
- `pid` (BIGINT): Process (or thread) ID
- `path` (TEXT): Path of executed file
- `mode` (TEXT): File mode permissions
- `cmdline` (TEXT): Command line arguments (argv)
- `cmdline_size` (BIGINT, HIDDEN): Actual size (bytes) of command line arguments
- `env` (TEXT, HIDDEN, alias:environment): Environment variables delimited by spaces
- `env_count` (BIGINT, HIDDEN, alias:environment_count): Number of environment variables
- `env_size` (BIGINT, HIDDEN, alias:environment_size): Actual size (bytes) of environment list
- `cwd` (TEXT): The process current working directory
- `auid` (BIGINT): Audit User ID at process start
- `uid` (BIGINT): User ID at process start
- `euid` (BIGINT): Effective user ID at process start
- `gid` (BIGINT): Group ID at process start
- `egid` (BIGINT): Effective group ID at process start
- `owner_uid` (BIGINT): File owner user ID
- `owner_gid` (BIGINT): File owner group ID
- `atime` (BIGINT, alias:access_time): File last access in UNIX time
- `mtime` (BIGINT, alias:modify_time): File modification in UNIX time
- `ctime` (BIGINT, alias:change_time): File last metadata change in UNIX time
- `btime` (BIGINT, alias:create_time): File creation in UNIX time
- `overflows` (TEXT, HIDDEN): List of structures that overflowed
- `parent` (BIGINT): Process parent's PID, or -1 if cannot be determined.
- `time` (BIGINT, ADDITIONAL): Time of execution in UNIX time
- `uptime` (BIGINT): Time of execution in system uptime
- `eid` (TEXT, HIDDEN): Event ID
- `status` (BIGINT, DARWIN): OpenBSM Attribute: Status of the process

### `es_process_events` (`darwin/es_process_events.table` | event subscriber)
Process execution events from EndpointSecurity.
- `version` (INTEGER): Version of EndpointSecurity event
- `seq_num` (BIGINT): Per event sequence number
- `global_seq_num` (BIGINT): Global sequence number
- `pid` (BIGINT): Process (or thread) ID
- `pidversion` (BIGINT): Process ID version
- `path` (TEXT): Path of executed file
- `parent` (BIGINT): Parent process ID
- `original_parent` (BIGINT): Original parent process ID in case of reparenting
- `session_id` (BIGINT): The identifier of the session that contains the process group.
- `responsible_pid` (BIGINT): The pid of the process responsible for this process.
- `responsible_pidversion` (BIGINT): The pidversion of the process responsible for this process.
- `parent_pidversion` (BIGINT): The pidversion of the parent process.
- `cmdline` (TEXT): Command line arguments (argv)
- `cmdline_count` (BIGINT): Number of command line arguments
- `env` (TEXT): Environment variables delimited by spaces
- `env_count` (BIGINT): Number of environment variables
- `cwd` (TEXT): The process current working directory
- `uid` (BIGINT): User ID of the process
- `euid` (BIGINT): Effective User ID of the process
- `gid` (BIGINT): Group ID of the process
- `egid` (BIGINT): Effective Group ID of the process
- `username` (TEXT): Username
- `signing_id` (TEXT): Signature identifier of the process
- `team_id` (TEXT): Team identifier of the process
- `cdhash` (TEXT): Codesigning hash of the process
- `platform_binary` (INTEGER): Indicates if the binary is Apple signed binary (1) or not (0)
- `exit_code` (INTEGER): Exit code of a process in case of an exit event
- `child_pid` (BIGINT): Process ID of a child process in case of a fork event
- `time` (BIGINT, ADDITIONAL): Time of execution in UNIX time
- `event_type` (TEXT): Type of EndpointSecurity event
- `eid` (TEXT, HIDDEN): Event ID
- `codesigning_flags` (TEXT): Codesigning flags matching one of these options, in a comma separated list: NOT_VALID, ADHOC, NOT_RUNTIME, INSTALLER. See kern/cs_blobs.h in XNU for descriptions.

### `es_process_file_events` (`darwin/es_process_file_events.table` | event subscriber)
File integrity monitoring events from EndpointSecurity including process context.
- `version` (INTEGER): Version of EndpointSecurity event
- `seq_num` (BIGINT): Per event sequence number
- `global_seq_num` (BIGINT): Global sequence number
- `pid` (BIGINT): Process (or thread) ID
- `parent` (BIGINT): Parent process ID
- `path` (TEXT): Path of executed file
- `filename` (TEXT): The source or target filename for the event
- `dest_filename` (TEXT): Destination filename for the event
- `event_type` (TEXT): Type of EndpointSecurity event
- `time` (BIGINT, ADDITIONAL): Time of execution in UNIX time
- `eid` (TEXT, HIDDEN): Event ID

### `running_apps` (`darwin/running_apps.table`)
macOS applications currently running on the host system.
- `pid` (INTEGER, INDEXED): The pid of the application
- `bundle_identifier` (TEXT): The bundle identifier of the application
- `is_active` (INTEGER, HIDDEN): (DEPRECATED)

### `launchd` (`darwin/launchd.table`)
LaunchAgents and LaunchDaemons from default search paths.
- `path` (TEXT, INDEXED): Path to daemon or agent plist
- `name` (TEXT): File name of plist (used by launchd)
- `label` (TEXT): Daemon or agent service name
- `program` (TEXT): Path to target program
- `run_at_load` (TEXT): Should the program run on launch load
- `keep_alive` (TEXT): Should the process be restarted if killed
- `on_demand` (TEXT): Deprecated key, replaced by keep_alive
- `disabled` (TEXT): Skip loading this daemon or agent on boot
- `username` (TEXT): Run this daemon or agent as this username
- `groupname` (TEXT): Run this daemon or agent as this group
- `stdout_path` (TEXT): Pipe stdout to a target path
- `stderr_path` (TEXT): Pipe stderr to a target path
- `start_interval` (TEXT): Frequency to run in seconds
- `program_arguments` (TEXT): Command line arguments passed to program
- `watch_paths` (TEXT): Key that launches daemon or agent if path is modified
- `queue_directories` (TEXT): Similar to watch_paths but only with non-empty directories
- `inetd_compatibility` (TEXT): Run this daemon or agent as it was launched from inetd
- `start_on_mount` (TEXT): Run daemon or agent every time a filesystem is mounted
- `root_directory` (TEXT): Key used to specify a directory to chroot to before launch
- `working_directory` (TEXT): Key used to specify a directory to chdir to before launch
- `process_type` (TEXT): Key describes the intended purpose of the job

### `launchd_overrides` (`darwin/launchd_overrides.table`)
Override keys, per user, for LaunchDaemons and Agents.
- `label` (TEXT): Daemon or agent service name
- `key` (TEXT): Name of the override key
- `value` (TEXT): Overridden value
- `uid` (BIGINT): User ID applied to the override, 0 applies to all
- `path` (TEXT): Path to daemon or agent plist

### `startup_items` (`startup_items.table`)
Applications and binaries set as startup items.
- `name` (TEXT): Name of startup item
- `path` (TEXT): Path of startup item
- `args` (TEXT): Arguments provided to startup executable
- `type` (TEXT): Type of startup item. On macOS this can be app, agent (LaunchAgent), daemon (LaunchDaemon), login item, or user item.
- `source` (TEXT): Directory containing startup item (on macOS, the subsystem providing it)
- `status` (TEXT): Startup status. On Linux: enabled or disabled. On macOS: Combination of enabled, allowed, notified, and hidden. Apple does not seem to document these status values, but allowed seems to indicate whether it is enabled in System Settings.
- `username` (TEXT): The user associated with the startup item

### `crontab` (`posix/crontab.table`)
Line parsed values from system and user cron/tab.
- `event` (TEXT): The job @event name (rare)
- `minute` (TEXT): The exact minute for the job
- `hour` (TEXT): The hour of the day for the job
- `day_of_month` (TEXT): The day of the month for the job
- `month` (TEXT): The month of the year for the job
- `day_of_week` (TEXT): The day of the week for the job
- `command` (TEXT): Raw command string
- `path` (TEXT): File parsed

### `event_taps` (`darwin/event_taps.table`)
Returns information about installed event taps.
- `enabled` (INTEGER): Is the Event Tap enabled
- `event_tap_id` (INTEGER): Unique ID for the Tap
- `event_tapped` (TEXT): The mask that identifies the set of events to be observed.
- `process_being_tapped` (INTEGER): The process ID of the target application
- `tapping_process` (INTEGER): The process ID of the application that created the event tap.

### `kernel_extensions` (`darwin/kernel_extensions.table`)
macOS's kernel extensions, both loaded and within the load search path.
- `idx` (INTEGER): Extension load tag or index
- `refs` (INTEGER): Reference count
- `size` (BIGINT): Bytes of wired memory used by extension
- `name` (TEXT): Extension label
- `version` (TEXT): Extension version
- `linked_against` (TEXT): Indexes of extensions this extension is linked against
- `path` (TEXT): Optional path to extension bundle

### `system_extensions` (`darwin/system_extensions.table`)
macOS (>= 10.15) system extension table.
- `path` (TEXT): Original path of system extension
- `UUID` (TEXT): Extension unique id
- `state` (TEXT): System extension state
- `identifier` (TEXT): Identifier name
- `version` (TEXT): System extension version
- `category` (TEXT): System extension category
- `bundle_path` (TEXT): System extension bundle path
- `team` (TEXT): Signing team ID
- `mdm_managed` (INTEGER): 1 if managed by MDM system extension payload configuration, 0 otherwise
- *Example*: `select * from system_extensions;`

### `carbon_black_info` (`carbon_black_info.table` | aliases: `cb_info`)
Returns info about a Carbon Black sensor install.
- `sensor_id` (INTEGER): Sensor ID of the Carbon Black sensor
- `config_name` (TEXT): Sensor group
- `collect_store_files` (INTEGER): If the sensor is configured to send back binaries to the Carbon Black server
- `collect_module_loads` (INTEGER): If the sensor is configured to capture module loads
- `collect_module_info` (INTEGER): If the sensor is configured to collect metadata of binaries
- `collect_file_mods` (INTEGER): If the sensor is configured to collect file modification events
- `collect_reg_mods` (INTEGER): If the sensor is configured to collect registry modification events
- `collect_net_conns` (INTEGER): If the sensor is configured to collect network connections
- `collect_processes` (INTEGER): If the sensor is configured to process events
- `collect_cross_processes` (INTEGER): If the sensor is configured to cross process events
- `collect_emet_events` (INTEGER): If the sensor is configured to EMET events
- `collect_data_file_writes` (INTEGER): If the sensor is configured to collect non binary file writes
- `collect_process_user_context` (INTEGER): If the sensor is configured to collect the user running a process
- `collect_sensor_operations` (INTEGER): Unknown
- `log_file_disk_quota_mb` (INTEGER): Event file disk quota in MB
- `log_file_disk_quota_percentage` (INTEGER): Event file disk quota in a percentage
- `protection_disabled` (INTEGER): If the sensor is configured to report tamper events
- `sensor_ip_addr` (TEXT): IP address of the sensor
- `sensor_backend_server` (TEXT): Carbon Black server
- `event_queue` (INTEGER): Size in bytes of Carbon Black event files on disk
- `binary_queue` (INTEGER): Size in bytes of binaries waiting to be sent to Carbon Black server

### `yara_process` (`yara_process.table`)
Triggers one-off YARA query for process memory of the specified pid. Additionally requires one of `sig_group`, `sigfile`, or `sigrule`.
- **Required `WHERE` constraint**: `pid`
- `pid` (INTEGER, REQUIRED): The pid scanned (process memory)
- `matches` (TEXT): List of YARA matches
- `count` (INTEGER): Number of YARA matches
- `sig_group` (TEXT, ADDITIONAL): Signature group used
- `sigfile` (TEXT, ADDITIONAL): Signature file used
- `sigrule` (TEXT, ADDITIONAL, HIDDEN): Signature strings used
- `strings` (TEXT): Matching strings
- `tags` (TEXT): Matching tags
- `sigurl` (TEXT, ADDITIONAL, HIDDEN): Signature url
- *Example*: `select * from yara_process where pid = 1234 and sigfile = '/etc/osquery/yara/test.yara';`

## 4. Network & Ports
Listening TCP/UDP ports, network interfaces, routing tables, ARP cache, DNS resolvers, `/etc/hosts`, Wi-Fi status and scan surveys, HTTP/TLS inspection (`curl`), and macOS file/screen sharing.

### `listening_ports` (`listening_ports.table`)
Processes with listening (bound) network sockets/ports.
- `pid` (INTEGER): Process (or thread) ID
- `port` (INTEGER): Transport layer port
- `protocol` (INTEGER): Transport protocol (TCP/UDP)
- `family` (INTEGER): Network protocol (IPv4, IPv6)
- `address` (TEXT): Specific address for bind
- `fd` (BIGINT): Socket file descriptor number
- `socket` (BIGINT): Socket handle or inode number
- `path` (TEXT): Path for UNIX domain sockets

### `interface_addresses` (`interface_addresses.table`)
Network interfaces and relevant metadata.
- `interface` (TEXT): Interface name
- `address` (TEXT): Specific address for interface
- `mask` (TEXT): Interface netmask
- `broadcast` (TEXT): Broadcast address for the interface
- `point_to_point` (TEXT): PtP address for the interface
- `type` (TEXT): Type of address. One of dhcp, manual, auto, other, unknown

### `interface_details` (`interface_details.table`)
Detailed information and stats of network interfaces.
- `interface` (TEXT): Interface name
- `mac` (TEXT): MAC of interface (optional)
- `type` (INTEGER): Interface type (includes virtual)
- `mtu` (INTEGER): Network MTU
- `metric` (INTEGER): Metric based on the speed of the interface
- `flags` (INTEGER): Flags (netdevice) for the device
- `ipackets` (BIGINT): Input packets
- `opackets` (BIGINT): Output packets
- `ibytes` (BIGINT): Input bytes
- `obytes` (BIGINT): Output bytes
- `ierrors` (BIGINT): Input errors
- `oerrors` (BIGINT): Output errors
- `idrops` (BIGINT): Input drops
- `odrops` (BIGINT): Output drops
- `collisions` (BIGINT): Packet Collisions detected
- `last_change` (BIGINT): Time of last device modification (optional)
- `link_speed` (BIGINT, DARWIN): Interface speed in Mb/s
- *Example*: `select interface, mac, type, idrops as input_drops from interface_details;`

### `interface_ipv6` (`posix/interface_ipv6.table`)
IPv6 configuration and stats of network interfaces.
- `interface` (TEXT): Interface name
- `hop_limit` (INTEGER): Current Hop Limit
- `forwarding_enabled` (INTEGER): Enable IP forwarding
- `redirect_accept` (INTEGER): Accept ICMP redirect messages
- `rtadv_accept` (INTEGER): Accept ICMP Router Advertisement

### `routes` (`routes.table`)
The active route table for the host system.
- `destination` (TEXT): Destination IP address
- `netmask` (INTEGER): Netmask length
- `gateway` (TEXT): Route gateway
- `source` (TEXT): Route source
- `flags` (INTEGER): Flags to describe route
- `interface` (TEXT): Route local interface
- `mtu` (INTEGER): Maximum Transmission Unit for the route
- `metric` (INTEGER): Cost of route. Lowest is preferred
- `type` (TEXT, ADDITIONAL): Type of route
- `hopcount` (INTEGER, DARWIN): Max hops expected

### `arp_cache` (`arp_cache.table`)
Address resolution cache, both static and dynamic (from ARP, NDP).
- `address` (TEXT): IPv4 address target
- `mac` (TEXT): MAC address of broadcasted address
- `interface` (TEXT): Interface of the network for the MAC
- `permanent` (TEXT): 1 for true, 0 for false

### `dns_resolvers` (`posix/dns_resolvers.table`)
Resolvers used by this host. Note: On Windows this data is available in the interface_details table.
- `id` (INTEGER): Address type index or order
- `type` (TEXT): Address type: sortlist, nameserver, search
- `address` (TEXT): Resolver IP/IPv6 address
- `netmask` (TEXT): Address (sortlist) netmask length
- `options` (BIGINT): Resolver options

### `etc_hosts` (`etc_hosts.table` | aliases: `hosts`)
Line-parsed /etc/hosts.
- `address` (TEXT): IP address mapping
- `hostnames` (TEXT): Raw hosts mapping

### `etc_protocols` (`etc_protocols.table`)
Line-parsed /etc/protocols.
- `name` (TEXT): Protocol name
- `number` (INTEGER): Protocol number
- `alias` (TEXT): Protocol alias
- `comment` (TEXT): Comment with protocol description

### `etc_services` (`etc_services.table`)
Line-parsed /etc/services.
- `name` (TEXT): Service name
- `port` (INTEGER): Service port number
- `protocol` (TEXT): Transport protocol (TCP/UDP)
- `aliases` (TEXT): Optional space separated list of other names for a service
- `comment` (TEXT): Optional comment for a service.

### `wifi_status` (`darwin/wifi_status.table`)
macOS current WiFi status. This table requires Full Disk Access (FDA) permission to retrieve network_name.
- `interface` (TEXT): Name of the interface
- `ssid` (TEXT): SSID octets of the network
- `bssid` (TEXT): The current basic service set identifier
- `network_name` (TEXT): Name of the network
- `country_code` (TEXT): The country code (ISO/IEC 3166-1:1997) for the network
- `security_type` (TEXT): Type of security on this network
- `rssi` (INTEGER): The current received signal strength indication (dbm)
- `noise` (INTEGER): The current noise measurement (dBm)
- `channel` (INTEGER): Channel number
- `channel_width` (INTEGER): Channel width
- `channel_band` (INTEGER): Channel band
- `transmit_rate` (TEXT): The current transmit rate
- `mode` (TEXT): The current operating mode for the Wi-Fi interface

### `wifi_networks` (`darwin/wifi_networks.table`)
macOS known/remembered Wi-Fi networks list.
- `ssid` (TEXT): SSID octets of the network
- `network_name` (TEXT): Name of the network
- `security_type` (TEXT): Type of security on this network
- `last_connected` (INTEGER, HIDDEN): Last time this network was connected to as a unix_time (max of last_connected_automatic and last_connected_manual, if available)
- `last_connected_automatic` (INTEGER): Last time this network was automatically connected to by the system as a unix_time
- `last_connected_manual` (INTEGER): Last time this network was manually connected to by the user as a unix_time
- `passpoint` (INTEGER, HIDDEN): 1 if Passpoint is supported, 0 otherwise
- `possibly_hidden` (INTEGER): 1 if network is possibly a hidden network, 0 otherwise
- `roaming` (INTEGER, HIDDEN): 1 if roaming is supported, 0 otherwise
- `roaming_profile` (TEXT): Describe the roaming profile, usually one of Single, Dual  or Multi
- `auto_login` (INTEGER, HIDDEN): 1 if auto login is enabled, 0 otherwise
- `temporarily_disabled` (INTEGER): 1 if this network is temporarily disabled, 0 otherwise
- `disabled` (INTEGER, HIDDEN): 1 if this network is disabled, 0 otherwise
- `add_reason` (TEXT): Shows why this network was added, via menubar or command line or something else
- `added_at` (INTEGER): Time this network was added as a unix_time
- `captive_portal` (INTEGER): 1 if this network has a captive portal, 0 otherwise
- `captive_login_date` (INTEGER): Time this network logged in to a captive portal as unix_time
- `was_captive_network` (INTEGER): 1 if this network was previously a captive network, 0 otherwise
- `auto_join` (INTEGER): 1 if this network set to join automatically, 0 otherwise
- `personal_hotspot` (INTEGER): 1 if this network is a personal hotspot, 0 otherwise

### `wifi_survey` (`darwin/wifi_scan.table`)
Scan for nearby WiFi networks.
- `interface` (TEXT): Name of the interface
- `ssid` (TEXT): SSID octets of the network
- `bssid` (TEXT): The current basic service set identifier
- `network_name` (TEXT): Name of the network
- `country_code` (TEXT): The country code (ISO/IEC 3166-1:1997) for the network
- `rssi` (INTEGER): The current received signal strength indication (dbm)
- `noise` (INTEGER): The current noise measurement (dBm)
- `channel` (INTEGER): Channel number
- `channel_width` (INTEGER): Channel width
- `channel_band` (INTEGER): Channel band

### `curl` (`curl.table`)
Perform an http request and return stats about it.
- **Required `WHERE` constraint**: `url`
- `url` (TEXT, REQUIRED): The url for the request
- `method` (TEXT): The HTTP method for the request
- `user_agent` (TEXT, ADDITIONAL): The user-agent string to use for the request
- `response_code` (INTEGER): The HTTP status code for the response
- `round_trip_time` (BIGINT): Time taken to complete the request
- `bytes` (BIGINT): Number of bytes in the response
- `result` (TEXT): The HTTP response body
- *Example*: `select url, round_trip_time, response_code from curl where url = 'https://github.com/osquery/osquery';`

### `curl_certificate` (`curl_certificate.table`)
Inspect TLS certificates by connecting to input hostnames.
- **Required `WHERE` constraint**: `hostname`
- `hostname` (TEXT, REQUIRED): Hostname to CURL (domain[:port], e.g. osquery.io)
- `common_name` (TEXT): Common name of company issued to
- `organization` (TEXT): Organization issued to
- `organization_unit` (TEXT): Organization unit issued to
- `serial_number` (TEXT): Certificate serial number
- `issuer_common_name` (TEXT): Issuer common name
- `issuer_organization` (TEXT): Issuer organization
- `issuer_organization_unit` (TEXT): Issuer organization unit
- `valid_from` (TEXT): Period of validity start date
- `valid_to` (TEXT): Period of validity end date
- `sha256_fingerprint` (TEXT): SHA-256 fingerprint
- `sha1_fingerprint` (TEXT): SHA1 fingerprint
- `version` (INTEGER): Version Number
- `signature_algorithm` (TEXT): Signature Algorithm
- `signature` (TEXT): Signature
- `subject_key_identifier` (TEXT): Subject Key Identifier
- `authority_key_identifier` (TEXT): Authority Key Identifier
- `key_usage` (TEXT): Usage of key in certificate
- `extended_key_usage` (TEXT): Extended usage of key in certificate
- `policies` (TEXT): Certificate Policies
- `subject_alternative_names` (TEXT): Subject Alternative Name
- `issuer_alternative_names` (TEXT): Issuer Alternative Name
- `info_access` (TEXT): Authority Information Access
- `subject_info_access` (TEXT): Subject Information Access
- `policy_mappings` (TEXT): Policy Mappings
- `has_expired` (INTEGER): 1 if the certificate has expired, 0 otherwise
- `basic_constraint` (TEXT): Basic Constraints
- `name_constraints` (TEXT): Name Constraints
- `policy_constraints` (TEXT): Policy Constraints
- `dump_certificate` (INTEGER, ADDITIONAL, HIDDEN): Set this value to '1' to dump certificate
- `timeout` (INTEGER, ADDITIONAL, HIDDEN): Set this value to the timeout in seconds to complete the TLS handshake (default 4s, use 0 for no timeout)
- `pem` (TEXT): Certificate PEM format
- `tls_version` (TEXT): TLS protocol version negotiated for the connection; empty if the handshake did not complete
- `cipher_suite` (TEXT): IANA name of the cipher suite negotiated for the connection; empty if the handshake did not complete
- `cipher_bits` (INTEGER): Number of secret/key bits used by the negotiated cipher suite; NULL if the handshake did not complete
- *Example*: `select * from curl_certificate where hostname = 'osquery.io' and dump_certificate = 1;`

### `socket_events` (`posix/socket_events.table` | event subscriber)
Track network socket bind, connect, and accepts.
- `action` (TEXT): The socket action (bind, connect, accept)
- `pid` (BIGINT): Process (or thread) ID
- `path` (TEXT): Path of executed file
- `fd` (TEXT): The file description for the process socket
- `auid` (BIGINT): Audit User ID
- `family` (INTEGER): The Internet protocol family ID
- `protocol` (INTEGER, HIDDEN): The network protocol ID
- `local_address` (TEXT): Local address associated with socket
- `remote_address` (TEXT): Remote address associated with socket
- `local_port` (INTEGER): Local network protocol port number
- `remote_port` (INTEGER): Remote network protocol port number
- `socket` (TEXT, HIDDEN): The local path (UNIX domain socket only)
- `time` (BIGINT, ADDITIONAL): Time of execution in UNIX time
- `uptime` (BIGINT): Time of execution in system uptime
- `eid` (TEXT, HIDDEN): Event ID
- `success` (INTEGER, HIDDEN): Deprecated. Use the 'status' column instead

### `sharing_preferences` (`darwin/sharing_preferences.table` | aliases: `alf_services`)
macOS Sharing preferences.
- `screen_sharing` (INTEGER): 1 If screen sharing is enabled else 0
- `file_sharing` (INTEGER): 1 If file sharing is enabled else 0
- `printer_sharing` (INTEGER): 1 If printer sharing is enabled else 0
- `remote_login` (INTEGER): 1 If remote login is enabled else 0
- `remote_management` (INTEGER): 1 If remote management is enabled else 0
- `remote_apple_events` (INTEGER): 1 If remote apple events are enabled else 0
- `internet_sharing` (INTEGER): 1 If internet sharing is enabled else 0
- `bluetooth_sharing` (INTEGER): 1 If bluetooth sharing is enabled for any user else 0
- `disc_sharing` (INTEGER): 1 If CD or DVD sharing is enabled else 0
- `content_caching` (INTEGER): 1 If content caching is enabled else 0

### `shared_folders` (`darwin/shared_folders.table`)
Folders available to others via SMB or AFP.
- `name` (TEXT): The shared name of the folder as it appears to other users
- `path` (TEXT): Absolute path of shared folder on the local system

### `nfs_shares` (`darwin/nfs_shares.table`)
NFS shares exported by the host.
- `share` (TEXT): Filesystem path to the share
- `options` (TEXT): Options string set on the export share
- `readonly` (INTEGER): 1 if the share is exported readonly else 0

### `cups_destinations` (`darwin/cups_destinations.table`)
Returns all configured printers.
- `name` (TEXT): Name of the printer
- `option_name` (TEXT): Option name
- `option_value` (TEXT): Option value

### `cups_jobs` (`darwin/cups_jobs.table`)
Returns all completed print jobs from cups.
- `title` (TEXT): Title of the printed job
- `destination` (TEXT): The printer the job was sent to
- `user` (TEXT): The user who printed the job
- `format` (TEXT): The format of the print job
- `size` (INTEGER): The size of the print job
- `completed_time` (INTEGER): When the job completed printing
- `processing_time` (INTEGER): How long the job took to process
- `creation_time` (INTEGER): When the print request was initiated

## 5. Filesystem, Disk & Spotlight
Mounted filesystems, block devices, FileVault encryption (`disk_encryption`), interactive file metadata (`file`), hashes (`hash`), macOS extended attributes (`xattr`), Spotlight search (`mdfind`, `mdls`), plists, and Time Machine backups.

### `mounts` (`posix/mounts.table`)
System mounted devices and filesystems (not process specific).
- `device` (TEXT): Mounted device
- `device_alias` (TEXT): Mounted device alias
- `path` (TEXT): Mounted device path
- `type` (TEXT): Mounted device type
- `blocks_size` (BIGINT): Block size in bytes
- `blocks` (BIGINT): Mounted device used blocks
- `blocks_free` (BIGINT): Mounted device blocks available to root users, a superset of blocks_available
- `blocks_available` (BIGINT): Mounted device blocks available to non-root users
- `inodes` (BIGINT): Mounted device used inodes
- `inodes_free` (BIGINT): Mounted device free inodes
- `flags` (TEXT): Mounted device flags

### `block_devices` (`posix/block_devices.table`)
Block (buffered access) device file nodes: disks, ramdisks, and DMG containers.
- `name` (TEXT, INDEXED): Block device name
- `parent` (TEXT): Block device parent name
- `vendor` (TEXT): Block device vendor string
- `model` (TEXT): Block device model string identifier
- `serial` (TEXT): Disk serial number
- `size` (BIGINT): Block device size in blocks
- `block_size` (INTEGER): Block size in bytes
- `uuid` (TEXT): Block device Universally Unique Identifier
- `type` (TEXT): Block device type string
- `label` (TEXT): Block device label string

### `disk_encryption` (`posix/disk_encryption.table`)
Disk encryption status and information.
- `name` (TEXT, INDEXED): Disk name
- `uuid` (TEXT): Disk Universally Unique Identifier
- `encrypted` (INTEGER): 1 If encrypted: true (disk is encrypted), else 0
- `type` (TEXT): Description of cipher type and mode if available
- `encryption_status` (TEXT): Disk encryption status with one of following values: encrypted | not encrypted | undefined
- `uid` (TEXT, DARWIN): Currently authenticated user if available
- `user_uuid` (TEXT, DARWIN): UUID of authenticated user if available
- `filevault_status` (TEXT, DARWIN): FileVault status with one of following values: on | off | unknown

### `disk_events` (`darwin/disk_events.table` | event subscriber)
Track DMG disk image events (appearance/disappearance) when opened.
- `action` (TEXT): Appear or disappear
- `path` (TEXT): Path of the DMG file accessed
- `name` (TEXT): Disk event name
- `device` (TEXT, alias:bsd_name): Disk event BSD name
- `uuid` (TEXT): UUID of the volume inside DMG if available
- `size` (BIGINT): Size of partition in bytes
- `ejectable` (INTEGER): 1 if ejectable, 0 if not
- `mountable` (INTEGER): 1 if mountable, 0 if not
- `writable` (INTEGER): 1 if writable, 0 if not
- `content` (TEXT): Disk event content
- `media_name` (TEXT): Disk event media name string
- `vendor` (TEXT): Disk event vendor string
- `filesystem` (TEXT): Filesystem if available
- `checksum` (TEXT): UDIF Master checksum if available (CRC32)
- `time` (BIGINT, ADDITIONAL): Time of appearance/disappearance in UNIX time
- `eid` (TEXT, HIDDEN): Event ID

### `file` (`utility/file.table`)
Interactive filesystem attributes and metadata.
- **Required `WHERE` constraint**: `path`, `directory`
- `path` (TEXT, REQUIRED): Absolute file path
- `directory` (TEXT, REQUIRED): Directory of file(s)
- `filename` (TEXT): Name portion of file path
- `inode` (BIGINT): Filesystem inode number
- `uid` (BIGINT): Owning user ID
- `gid` (BIGINT): Owning group ID
- `mode` (TEXT): Permission bits
- `device` (BIGINT): Device ID (optional)
- `size` (BIGINT): Size of file in bytes
- `block_size` (INTEGER): Block size of filesystem
- `atime` (BIGINT): Last access time
- `mtime` (BIGINT): Last modification time
- `ctime` (BIGINT): Last status change time
- `btime` (BIGINT): (B)irth or (cr)eate time
- `hard_links` (INTEGER): Number of hard links
- `symlink` (INTEGER): 1 if the path is a symlink, otherwise 0
- `type` (TEXT): File status
- `symlink_target_path` (TEXT): Full path of the symlink target if any
- `bsd_flags` (TEXT, DARWIN): The BSD file flags (chflags). Possible values: NODUMP, UF_IMMUTABLE, UF_APPEND, OPAQUE, HIDDEN, ARCHIVED, SF_IMMUTABLE, SF_APPEND
- *Example*: `select * from file where path = '/etc/passwd'; select * from file where directory = '/etc/';`

### `file_events` (`posix/file_events.table` | event subscriber)
Track time/action changes to files specified in configuration data.
- `target_path` (TEXT): The path associated with the event
- `category` (TEXT): The category of the file defined in the config
- `action` (TEXT): Change action (UPDATE, REMOVE, etc)
- `transaction_id` (BIGINT): ID used during bulk update
- `inode` (BIGINT): Filesystem inode number
- `uid` (BIGINT): Owning user ID
- `gid` (BIGINT): Owning group ID
- `mode` (TEXT): Permission bits
- `size` (BIGINT): Size of file in bytes
- `atime` (BIGINT): Last access time
- `mtime` (BIGINT): Last modification time
- `ctime` (BIGINT): Last status change time
- `md5` (TEXT): The MD5 of the file after change
- `sha1` (TEXT): The SHA1 of the file after change
- `sha256` (TEXT): The SHA256 of the file after change
- `hashed` (INTEGER): 1 if the file was hashed, 0 if not, -1 if hashing failed
- `time` (BIGINT, ADDITIONAL): Time of file event
- `eid` (TEXT, HIDDEN): Event ID

### `hash` (`hash.table`)
Filesystem hash data.
- **Required `WHERE` constraint**: `path`, `directory`
- `path` (TEXT, REQUIRED): Must provide a path or directory
- `directory` (TEXT, REQUIRED): Must provide a path or directory
- `md5` (TEXT): MD5 hash of provided filesystem data
- `sha1` (TEXT): SHA1 hash of provided filesystem data
- `sha256` (TEXT): SHA256 hash of provided filesystem data
- *Example*: `select * from hash where path = '/etc/passwd'; select * from hash where directory = '/etc/';`

### `extended_attributes` (`posix/extended_attributes.table`)
Returns the extended attributes for files (similar to Windows ADS).
- **Required `WHERE` constraint**: `path`, `directory`
- `path` (TEXT, REQUIRED): Absolute file path
- `directory` (TEXT, REQUIRED): Directory of file(s)
- `key` (TEXT): Name of the value generated from the extended attribute
- `value` (TEXT): The parsed information from the attribute
- `base64` (INTEGER): 1 if the value is base64 encoded else 0

### `mdfind` (`darwin/mdfind.table`)
Run searches against the spotlight database.
- **Required `WHERE` constraint**: `query`
- `path` (TEXT): Path of the file returned from spotlight
- `query` (TEXT, REQUIRED): The query that was run to find the file
- *Example*: `select * from mdfind where query = 'kMDItemDisplayName == "rook.stl"';`

### `mdls` (`darwin/mdls.table`)
Query file metadata in the Spotlight database.
- **Required `WHERE` constraint**: `path`
- `path` (TEXT, REQUIRED): Path of the file
- `key` (TEXT): Name of the metadata key
- `value` (TEXT): Value stored in the metadata key
- `valuetype` (TEXT, HIDDEN): CoreFoundation type of data stored in value
- *Example*: `select * from mdls where path = '/Users/testuser/Desktop/testfile';`

### `plist` (`darwin/plist.table`)
Read and parse a plist file.
- **Required `WHERE` constraint**: `path`
- `key` (TEXT): Preference top-level key
- `subkey` (TEXT): Intermediate key path, includes lists/dicts
- `value` (TEXT): String value of most CF types
- `path` (TEXT, REQUIRED): (required) read preferences from a plist
- *Example*: `select * from plist where path = '/Library/Preferences/loginwindow.plist';`

### `magic` (`posix/magic.table`)
Magic number recognition library table.
- **Required `WHERE` constraint**: `path`
- `path` (TEXT, REQUIRED): Absolute path to target file
- `magic_db_files` (TEXT, ADDITIONAL): Colon(:) separated list of files where the magic db file can be found. By default one of the following is used: /usr/share/file/magic/magic, /usr/share/misc/magic or /usr/share/misc/magic.mgc
- `data` (TEXT): Magic number data from libmagic
- `mime_type` (TEXT): MIME type data from libmagic
- `mime_encoding` (TEXT): MIME encoding data from libmagic

### `quicklook_cache` (`darwin/quicklook_cache.table`)
Files and thumbnails within macOS's Quicklook Cache.
- `path` (TEXT): Path of file
- `rowid` (INTEGER): Quicklook file rowid key
- `fs_id` (TEXT): Quicklook file fs_id key
- `volume_id` (INTEGER): Parsed volume ID from fs_id
- `inode` (INTEGER): Parsed file ID (inode) from fs_id
- `mtime` (INTEGER): Parsed version date field
- `size` (BIGINT): Parsed version size field
- `label` (TEXT): Parsed version 'gen' field
- `last_hit_date` (INTEGER): Apple date format for last thumbnail cache hit
- `hit_count` (TEXT): Number of cache hits on thumbnail
- `icon_mode` (BIGINT): Thumbnail icon mode
- `cache_path` (TEXT): Path to cache data

### `time_machine_backups` (`darwin/time_machine_backups.table`)
Backups to drives using TimeMachine. This table requires Full Disk Access (FDA) permission.
- `destination_id` (TEXT): Time Machine destination ID
- `backup_date` (INTEGER): Backup Date
- *Example*: `select alias, backup_date, td.destination_id, root_volume_uuid, encryption from time_machine_backups tb join time_machine_destinations td on (td.destination_id=tb.destination_id);`

### `time_machine_destinations` (`darwin/time_machine_destinations.table`)
Locations backed up to using Time Machine. This table requires Full Disk Access (FDA) permission.
- `alias` (TEXT): Human readable name of drive
- `destination_id` (TEXT): Time Machine destination ID
- `consistency_scan_date` (INTEGER): Consistency scan date
- `root_volume_uuid` (TEXT): Root UUID of backup volume
- `bytes_available` (INTEGER): Bytes available on volume
- `bytes_used` (INTEGER): Bytes used on volume
- `encryption` (TEXT): Last known encrypted state
- *Example*: `select alias, backup_date, td.destination_id, root_volume_uuid, encryption from time_machine_backups tb join time_machine_destinations td on (td.destination_id=tb.destination_id);`

### `augeas` (`posix/augeas.table` | aliases: `configurations`)
Configuration files parsed by augeas.
- `node` (TEXT, INDEXED): The node path of the configuration item
- `value` (TEXT): The value of the configuration item
- `label` (TEXT): The label of the configuration item
- `path` (TEXT, ADDITIONAL): The path to the configuration file
- *Example*: `select * from augeas where path = '/etc/hosts';`

### `carves` (`carves.table`)
List the set of completed and in-progress carves. If carve=1 then the query is treated as a new carve request.
- `time` (BIGINT): Time at which the carve was kicked off
- `sha256` (TEXT): A SHA256 sum of the carved archive
- `size` (BIGINT): Size in bytes of the carved archive
- `path` (TEXT, ADDITIONAL): The path of the requested carve
- `status` (TEXT): Status of the carve, can be STARTING, PENDING, SUCCESS, or FAILED
- `carve_guid` (TEXT, INDEXED): Identifying value of the carve session
- `request_id` (TEXT): Identifying value of the carve request (e.g., scheduled query name, distributed request, etc)
- `carve` (INTEGER, ADDITIONAL): Set this value to '1' to start a file carve
- *Example*: `select * from carves; select * from carves where status like '%FAIL%';`

### `device_file` (`sleuthkit/device_file.table`)
Similar to the file table, but use TSK and allow block address access.
- **Required `WHERE` constraint**: `device`, `partition`
- `device` (TEXT, REQUIRED): Absolute file path to device node
- `partition` (TEXT, REQUIRED): A partition number
- `path` (TEXT, ADDITIONAL): A logical path within the device node
- `filename` (TEXT): Name portion of file path
- `inode` (BIGINT, INDEXED): Filesystem inode number
- `uid` (BIGINT): Owning user ID
- `gid` (BIGINT): Owning group ID
- `mode` (TEXT): Permission bits
- `size` (BIGINT): Size of file in bytes
- `block_size` (INTEGER): Block size of filesystem
- `atime` (BIGINT): Last access time
- `mtime` (BIGINT): Last modification time
- `ctime` (BIGINT): Creation time
- `hard_links` (INTEGER): Number of hard links
- `type` (TEXT): File status

### `device_hash` (`sleuthkit/device_hash.table`)
Similar to the hash table, but use TSK and allow block address access.
- **Required `WHERE` constraint**: `device`, `partition`, `inode`
- `device` (TEXT, REQUIRED): Absolute file path to device node
- `partition` (TEXT, REQUIRED): A partition number
- `inode` (BIGINT, REQUIRED): Filesystem inode number
- `md5` (TEXT): MD5 hash of provided inode data
- `sha1` (TEXT): SHA1 hash of provided inode data
- `sha256` (TEXT): SHA256 hash of provided inode data

### `device_partitions` (`sleuthkit/device_partitions.table`)
Use TSK to enumerate details about partitions on a disk device.
- **Required `WHERE` constraint**: `device`
- `device` (TEXT, REQUIRED): Absolute file path to device node
- `partition` (INTEGER): A partition number or description
- `label` (TEXT): The partition name as stored in the partition table
- `type` (TEXT): Filesystem type if recognized, otherwise, 'meta', 'normal', or 'unallocated'
- `offset` (BIGINT): Byte offset from the start of the volume
- `blocks_size` (BIGINT): Byte size of each block
- `blocks` (BIGINT): Number of blocks
- `inodes` (BIGINT): Number of meta nodes
- `flags` (INTEGER): Value that describes the partition (TSK_VS_PART_FLAG_ENUM)

### `yara_file` (`yara_file.table` | aliases: `yara`)
Triggers one-off YARA query for files at the specified path. Additionally requires one of `sig_group`, `sigfile`, or `sigrule`.
- **Required `WHERE` constraint**: `path`
- `path` (TEXT, REQUIRED): The path scanned
- `matches` (TEXT): List of YARA matches
- `count` (INTEGER): Number of YARA matches
- `sig_group` (TEXT, ADDITIONAL): Signature group used
- `sigfile` (TEXT, ADDITIONAL): Signature file used
- `sigrule` (TEXT, ADDITIONAL, HIDDEN): Signature strings used
- `strings` (TEXT): Matching strings
- `tags` (TEXT): Matching tags
- `sigurl` (TEXT, ADDITIONAL, HIDDEN): Signature url
- *Example*: `select * from yara_file where path = '/etc/passwd' and sigfile = '/etc/osquery/yara/test.yara';`

### `yara_events` (`yara_events.table` | event subscriber)
Track YARA matches for files specified in configuration data.
- `target_path` (TEXT): The path scanned
- `category` (TEXT): The category of the file
- `action` (TEXT): Change action (UPDATE, REMOVE, etc)
- `matches` (TEXT): List of YARA matches
- `count` (INTEGER): Number of YARA matches
- `strings` (TEXT): Matching strings
- `tags` (TEXT): Matching tags
- `time` (BIGINT): Time of the scan
- `eid` (TEXT, HIDDEN): Event ID
- `transaction_id` (BIGINT, DARWIN): ID used during bulk update

## 6. Users, Security, SIP & Keychain
Local and directory users/groups, active logins, SSH keys, `sudoers`, System Integrity Protection (`sip_config`), Gatekeeper, Application Layer Firewall (`alf`), XProtect, Keychain items/ACLs, code signatures, entitlements (`sandboxes`), and MDM profiles (`managed_policies`).

### `users` (`users.table`)
Local user accounts (including domain accounts that have logged on locally (Windows)).
- `uid` (BIGINT, INDEXED): User ID
- `gid` (BIGINT): Group ID (unsigned)
- `uid_signed` (BIGINT): User ID as int64 signed (Apple)
- `gid_signed` (BIGINT): Default group ID as int64 signed (Apple)
- `username` (TEXT, ADDITIONAL): Username
- `description` (TEXT): Optional user description
- `directory` (TEXT): User's home directory
- `shell` (TEXT): User's configured default shell
- `uuid` (TEXT, INDEXED): User's UUID (Apple) or SID (Windows)
- `is_hidden` (INTEGER, DARWIN): IsHidden attribute set in OpenDirectory
- *Example*: `select * from users where uid = 1000; select * from users where username = 'root';`

### `groups` (`groups.table`)
Local system groups.
- `gid` (BIGINT, INDEXED): Unsigned int64 group ID
- `gid_signed` (BIGINT): A signed int64 version of gid
- `groupname` (TEXT): Canonical local group name
- `is_hidden` (INTEGER, DARWIN): IsHidden attribute set in OpenDirectory
- *Example*: `select * from groups where gid = 0;`

### `user_groups` (`user_groups.table`)
Local system user group relationships.
- `uid` (BIGINT, INDEXED): User ID
- `gid` (BIGINT, INDEXED): Group ID

### `logged_in_users` (`logged_in_users.table`)
Users with an active shell on the system.
- `type` (TEXT): Login type
- `user` (TEXT): User login name
- `tty` (TEXT): Device name
- `host` (TEXT): Remote hostname
- `time` (BIGINT): Time entry was made
- `pid` (INTEGER): Process (or thread) ID

### `last` (`posix/last.table`)
System logins and logouts.
- `username` (TEXT): Entry username
- `tty` (TEXT): Entry terminal
- `pid` (INTEGER): Process (or thread) ID
- `type` (INTEGER): Entry type, according to ut_type types (utmp.h)
- `type_name` (TEXT): Entry type name, according to ut_type types (utmp.h)
- `time` (INTEGER): Entry timestamp
- `host` (TEXT): Entry hostname

### `user_events` (`posix/user_events.table` | event subscriber)
Track user events from the audit framework.
- `uid` (BIGINT): User ID
- `auid` (BIGINT): Audit User ID
- `pid` (BIGINT): Process (or thread) ID
- `message` (TEXT): Message from the event
- `type` (INTEGER): The file description for the process socket
- `path` (TEXT): Supplied path from event
- `address` (TEXT): The Internet protocol address or family ID
- `terminal` (TEXT): The network protocol ID
- `time` (BIGINT, ADDITIONAL): Time of execution in UNIX time
- `uptime` (BIGINT): Time of execution in system uptime
- `eid` (TEXT, HIDDEN): Event ID

### `user_interaction_events` (`darwin/user_interaction_events.table` | event subscriber)
Track user interaction events from macOS' event tapping framework.
- `time` (BIGINT, ADDITIONAL): Time

### `shell_history` (`posix/shell_history.table` | joins with `users`)
A line-delimited (command) table of per-user .*_history data.
- `uid` (BIGINT, INDEXED, ADDITIONAL): Shell history owner
- `time` (INTEGER): Entry timestamp. It could be absent, default value is 0.
- `command` (TEXT): Unparsed date/line/command history line
- `history_file` (TEXT): Path to the .*_history for this user
- *Example*: `select * from users join shell_history using (uid);`

### `sudoers` (`posix/sudoers.table`)
Rules for running commands as other users via sudo.
- `source` (TEXT): Source file containing the given rule
- `header` (TEXT): Symbol for given rule
- `rule_details` (TEXT): Rule definition

### `suid_bin` (`posix/suid_bin.table`)
suid binaries in common locations.
- `path` (TEXT): Binary path
- `username` (TEXT): Binary owner username
- `groupname` (TEXT): Binary owner group
- `permissions` (TEXT): Binary permissions

### `ssh_configs` (`ssh_configs.table` | joins with `users`)
A table of parsed ssh_configs.
- `uid` (BIGINT, INDEXED, ADDITIONAL): The local owner of the ssh_config file
- `block` (TEXT): The host or match block
- `option` (TEXT): The option and value
- `ssh_config_file` (TEXT): Path to the ssh_config file
- *Example*: `select * from users join ssh_configs using (uid);`

### `user_ssh_keys` (`user_ssh_keys.table` | joins with `users`)
Returns the private keys in the users ~/.ssh directory and whether or not they are encrypted.
- `uid` (BIGINT, INDEXED, ADDITIONAL): The local user that owns the key file
- `path` (TEXT, INDEXED): Path to key file
- `encrypted` (INTEGER): 1 if key is encrypted, 0 otherwise
- `key_type` (TEXT): The type of the private key. One of [rsa, dsa, dh, ec, hmac, cmac], or the empty string.
- `key_group_name` (TEXT): The group of the private key. Supported for a subset of key_types implemented by OpenSSL
- `key_length` (INTEGER): The cryptographic length of the cryptosystem to which the private key belongs, in bits. Definition of cryptographic length is specific to cryptosystem. -1 if unavailable
- `key_security_bits` (INTEGER): The number of security bits of the private key, bits of security as defined in NIST SP800-57. -1 if unavailable
- *Example*: `select * from users join user_ssh_keys using (uid) where encrypted = 0;`

### `authorized_keys` (`posix/authorized_keys.table` | joins with `users`)
A line-delimited authorized_keys table.
- `uid` (BIGINT, ADDITIONAL): The local owner of authorized_keys file
- `algorithm` (TEXT): Key type
- `key` (TEXT): Key encoded as base64
- `options` (TEXT): Optional list of login options
- `comment` (TEXT): Optional comment
- `key_file` (TEXT): Path to the authorized_keys file
- *Example*: `select * from users join authorized_keys using (uid);`

### `known_hosts` (`posix/known_hosts.table` | joins with `users`)
A line-delimited known_hosts table.
- `uid` (BIGINT, INDEXED): The local user that owns the known_hosts file
- `key` (TEXT): parsed authorized keys line
- `key_file` (TEXT): Path to known_hosts file
- *Example*: `select * from users join known_hosts using (uid);`

### `account_policy_data` (`darwin/account_policy_data.table`)
Additional macOS user account data from the AccountPolicy section of OpenDirectory.
- `uid` (BIGINT): User ID
- `creation_time` (DOUBLE): When the account was first created
- `failed_login_count` (BIGINT): The number of failed login attempts using an incorrect password. Count resets after a correct password is entered.
- `failed_login_timestamp` (DOUBLE): The time of the last failed login attempt. Resets after a correct password is entered
- `password_last_set_time` (DOUBLE): The time the password was last changed
- *Example*: `select * from users join account_policy_data using (uid);`

### `password_policy` (`darwin/password_policy.table`)
OpenDirectory account policies for macOS including password content, authentication, and password change policies.
- `uid` (BIGINT, INDEXED): User ID for the policy, -1 for policies that are global
- `policy_identifier` (TEXT): Policy Identifier
- `policy_content` (TEXT): Policy content
- `policy_description` (TEXT): Policy description
- `policy_category` (TEXT): Policy category: passwordPolicyAuthentication, passwordPolicyPasswordChange, or passwordPolicyPasswordContent
- `policy_parameters` (TEXT): Policy parameters serialized as JSON
- *Example*: `select * from password_policy; select * from password_policy where policy_category = 'policyCategoryPasswordContent';`

### `ad_config` (`darwin/ad_config.table`)
macOS Active Directory configuration.
- `name` (TEXT): The macOS-specific configuration name
- `domain` (TEXT): Active Directory trust domain
- `option` (TEXT): Canonical name of option
- `value` (TEXT): Variable typed option value

### `authorizations` (`darwin/authorizations.table`)
macOS Authorization rights database.
- `label` (TEXT, INDEXED): Item name, usually in reverse domain format
- `modified` (TEXT): Label top-level key
- `allow_root` (TEXT): Label top-level key
- `timeout` (TEXT): Label top-level key
- `version` (TEXT): Label top-level key
- `tries` (TEXT): Label top-level key
- `authenticate_user` (TEXT): Label top-level key
- `shared` (TEXT): Label top-level key
- `comment` (TEXT): Label top-level key
- `created` (TEXT): Label top-level key
- `class` (TEXT): Label top-level key
- `session_owner` (TEXT): Label top-level key
- *Example*: `select * from authorizations; select * from authorizations where label = 'system.login.console';`

### `authorization_mechanisms` (`darwin/authorization_mechanisms.table`)
macOS Authorization mechanisms database.
- `label` (TEXT, INDEXED): Label of the authorization right
- `plugin` (TEXT): Authorization plugin name
- `mechanism` (TEXT): Name of the mechanism that will be called
- `privileged` (TEXT): If privileged it will run as root, else as an anonymous user
- `entry` (TEXT): The whole string entry
- *Example*: `select * from authorization_mechanisms; select * from authorization_mechanisms where label = 'system.login.console';`

### `sip_config` (`darwin/sip_config.table`)
Apple's System Integrity Protection (rootless) status.
- `config_flag` (TEXT): The System Integrity Protection config flag
- `enabled` (INTEGER): 1 if this configuration is enabled, otherwise 0
- `enabled_nvram` (INTEGER): 1 if this configuration is enabled, otherwise 0
- *Example*: `select * from sip_config;`

### `gatekeeper` (`darwin/gatekeeper.table`)
macOS Gatekeeper Details.
- `assessments_enabled` (INTEGER): 1 If a Gatekeeper is enabled else 0
- `dev_id_enabled` (INTEGER): 1 If a Gatekeeper allows execution from identified developers else 0
- `version` (TEXT): Version of Gatekeeper's gke.bundle
- `opaque_version` (TEXT): Version of Gatekeeper's gkopaque.bundle

### `gatekeeper_approved_apps` (`darwin/gatekeeper_approved_apps.table`)
Gatekeeper apps a user has allowed to run.
- `path` (TEXT): Path of executable allowed to run
- `requirement` (TEXT): Code signing requirement language
- `ctime` (DOUBLE): Last change time
- `mtime` (DOUBLE): Last modification time

### `alf` (`darwin/alf.table`)
macOS application layer firewall (ALF) service details.
- `allow_signed_enabled` (INTEGER): 1 If allow signed mode is enabled else 0 (not supported on macOS 15+)
- `firewall_unload` (INTEGER): 1 If firewall unloading enabled else 0 (not supported on macOS 15+)
- `global_state` (INTEGER): 1 If the firewall is enabled with exceptions, 2 if the firewall is configured to block all incoming connections, else 0
- `logging_enabled` (INTEGER): 1 If logging mode is enabled else 0
- `logging_option` (INTEGER): Firewall logging option (not supported on macOS 15+)
- `stealth_enabled` (INTEGER): 1 If stealth mode is enabled else 0
- `version` (TEXT): Application Layer Firewall version

### `alf_exceptions` (`darwin/alf_exceptions.table`)
macOS application layer firewall (ALF) service exceptions.
- `path` (TEXT): Path to the executable that is excepted. On macOS 15+ this can also be a bundle identifier
- `state` (INTEGER): Firewall exception state. 0 if the application is configured to allow incoming connections, 2 if the application is configured to block incoming connections and 3 if the application is configuted to allow incoming connections but with additional restrictions.

### `alf_explicit_auths` (`darwin/alf_explicit_auths.table`)
ALF services explicitly allowed to perform networking. Not supported on macOS 15+ (returns no results).
- `process` (TEXT): Process name that is explicitly allowed

### `xprotect_entries` (`darwin/xprotect_entries.table`)
Database of the machine's XProtect signatures.
- `name` (TEXT): Description of XProtected malware
- `launch_type` (TEXT): Launch services content type
- `identity` (TEXT): XProtect identity (SHA1) of content
- `filename` (TEXT): Use this file name to match
- `filetype` (TEXT): Use this file type to match
- `optional` (INTEGER): Match any of the identities/patterns for this XProtect name
- `uses_pattern` (INTEGER): Uses a match pattern instead of identity

### `xprotect_meta` (`darwin/xprotect_meta.table`)
Database of the machine's XProtect browser-related signatures.
- `identifier` (TEXT): Browser plugin or extension identifier
- `type` (TEXT): Either plugin or extension
- `developer_id` (TEXT): Developer identity (SHA1) of extension
- `min_version` (TEXT): The minimum allowed plugin version.

### `xprotect_reports` (`darwin/xprotect_reports.table`)
Database of XProtect matches (if user generated/sent an XProtect report).
- `name` (TEXT): Description of XProtected malware
- `user_action` (TEXT): Action taken by user after prompted
- `time` (TEXT): Quarantine alert time

### `keychain_items` (`darwin/keychain_items.table`)
Generic details about keychain items. NOTE: osquery limits frequent access to keychain files. This limit is controlled by keychain_access_interval flag.
- `label` (TEXT): Generic item name
- `description` (TEXT): Optional item description
- `comment` (TEXT): Optional keychain comment
- `account` (TEXT): Optional item account
- `created` (TEXT): Date item was created
- `modified` (TEXT): Date of last modification
- `type` (TEXT): Keychain item type (class)
- `pk_hash` (TEXT): Hash of associated public key (SHA1 of subjectPublicKey, see RFC 8520 4.2.1.2)
- `path` (TEXT, INDEXED, ADDITIONAL): Path to keychain containing item

### `keychain_acls` (`darwin/keychain_acls.table`)
Applications that have ACL entries in the keychain. NOTE: osquery limits frequent access to keychain files. This limit is controlled by keychain_access_interval flag.
- `keychain_path` (TEXT): The path of the keychain
- `authorizations` (TEXT): A space delimited set of authorization attributes
- `path` (TEXT): The path of the authorized application
- `description` (TEXT): The description included with the ACL entry
- `label` (TEXT): An optional label tag that may be included with the keychain entry
- *Example*: `select label, description, authorizations, path, count(path) as c from keychain_acls where label != '' and path != '' group by label having c > 1;`

### `certificates` (`certificates.table`)
Certificate Authorities installed in Keychains/ca-bundles. NOTE: osquery limits frequent access to keychain files on macOS. This limit is controlled by keychain_access_interval flag. On macOS, 'path' may point to either a keychain file or a DER/PEM-encoded certificate file; non-keychain files are parsed as DER/PEM.
- `common_name` (TEXT): Certificate CommonName
- `subject` (TEXT): Certificate distinguished name (deprecated, use subject2)
- `subject2` (TEXT): Certificate distinguished name
- `issuer` (TEXT): Certificate issuer distinguished name (deprecated, use issuer2)
- `issuer2` (TEXT): Certificate issuer distinguished name
- `ca` (INTEGER): 1 if CA: true (certificate is an authority) else 0
- `self_signed` (INTEGER): 1 if self-signed, else 0
- `not_valid_before` (DATETIME): Lower bound of valid date
- `not_valid_after` (DATETIME): Certificate expiration data
- `signing_algorithm` (TEXT): Signing algorithm used
- `key_algorithm` (TEXT): Key algorithm used
- `key_strength` (TEXT): Key size used for RSA/DSA, or curve name
- `key_usage` (TEXT): Certificate key usage and extended key usage
- `subject_key_id` (TEXT): SKID an optionally included SHA1
- `authority_key_id` (TEXT): AKID an optionally included SHA1
- `sha1` (TEXT): SHA1 hash of the raw certificate contents
- `path` (TEXT, INDEXED, ADDITIONAL): Path to Keychain or PEM bundle
- `serial` (TEXT): Certificate serial number

### `certificate_trust_settings` (`darwin/certificate_trust_settings.table`)
Certificate Authorities trust settings installed in Keychains/ca-bundles.
- `common_name` (TEXT): Certificate common name
- `serial` (TEXT): Certificate serial number
- `trust_domain` (TEXT, INDEXED): Certificate trust settings domain
- `trust_policy_name` (TEXT): Certificate trust policy name
- `trust_policy_data` (TEXT): Certificate trust policy data
- `trust_allowed_error` (TEXT): Certificate trust allowed error
- `trust_key_usage` (TEXT): Certificate trust key usage
- `trust_result` (TEXT): Certificate trust result
- *Example*: `select * from certificate_trust_settings where trust_domain = 'admin';`

### `signature` (`darwin/signature.table`)
File (executable, bundle, installer, disk) code signing status.
- **Required `WHERE` constraint**: `path`
- `path` (TEXT, REQUIRED): Must provide a path or directory
- `hash_resources` (INTEGER, ADDITIONAL): Set to 1 to also hash resources, or 0 otherwise. Default is 1
- `hash_executable` (INTEGER, ADDITIONAL): Set to 1 to also hash the executable, or 0 otherwise. Default is 1
- `arch` (TEXT): If applicable, the arch of the signed code
- `signed` (INTEGER): 1 If the file is signed else 0
- `identifier` (TEXT): The signing identifier sealed into the signature
- `cdhash` (TEXT): Hash of the application Code Directory
- `team_identifier` (TEXT): The team signing identifier sealed into the signature
- `authority` (TEXT): Certificate Common Name
- `entitlements` (TEXT): JSON representation of the code signing entitlements
- *Example*: `SELECT * FROM signature WHERE path = '/bin/ls'; SELECT * FROM signature WHERE path = '/Applications/Xcode.app' AND hash_resources=0;`

### `sandboxes` (`darwin/sandboxes.table`)
macOS application sandboxes container details.
- `label` (TEXT): UTI-format bundle or label ID
- `user` (TEXT): Sandbox owner
- `enabled` (INTEGER): Application sandboxings enabled on container
- `build_id` (TEXT): Sandbox-specific identifier
- `bundle_path` (TEXT): Application bundle used by the sandbox
- `path` (TEXT): Path to sandbox container directory

### `screenlock` (`darwin/screenlock.table`)
macOS screenlock status. Note: only fetches results for osquery's current logged-in user context. The user must also have recently logged in.
- `enabled` (INTEGER): 1 If a password is required after sleep or the screensaver begins; else 0
- `grace_period` (INTEGER): The amount of time in seconds the screen must be asleep or the screensaver on before a password is required on-wake. 0 = immediately; -1 = no password is required on-wake

### `secureboot` (`secureboot.table`)
Secure Boot UEFI Settings.
- `secure_boot` (INTEGER): Whether secure boot is enabled
- `secure_mode` (INTEGER, DARWIN): (Intel) Secure mode: 0 disabled, 1 full security, 2 medium security
- `description` (TEXT, DARWIN): (Apple Silicon) Human-readable description: 'Full Security', 'Reduced Security', or 'Permissive Security'
- `kernel_extensions` (INTEGER, DARWIN): (Apple Silicon) Allow user management of kernel extensions from identified developers (1 if allowed)
- `mdm_operations` (INTEGER, DARWIN): (Apple Silicon) Allow remote (MDM) management of kernel extensions and automatic software updates (1 if allowed)

### `location_services` (`darwin/location_services.table`)
Reports the status of the Location Services feature of the OS.
- `enabled` (INTEGER): 1 if Location Services are enabled, else 0

### `managed_policies` (`darwin/managed_policies.table`)
The managed configuration policies from AD, MDM, MCX, etc.
- `domain` (TEXT): System or manager-chosen domain key
- `uuid` (TEXT): Optional UUID assigned to policy set
- `name` (TEXT): Policy key name
- `value` (TEXT): Policy value
- `username` (TEXT): Policy applies only this user
- `manual` (INTEGER): 1 if policy was loaded manually, otherwise 0

### `preferences` (`darwin/preferences.table` | joins with `users`)
macOS defaults and managed preferences.
- `domain` (TEXT, INDEXED): Application ID usually in com.name.product format
- `key` (TEXT, INDEXED): Preference top-level key
- `subkey` (TEXT): Intemediate key path, includes lists/dicts
- `value` (TEXT): String value of most CF types
- `forced` (INTEGER): 1 if the value is forced/managed, else 0
- `username` (TEXT, ADDITIONAL): (optional) read preferences for a specific user
- `host` (TEXT): 'current' or 'any' host, where 'current' takes precedence
- *Example*: `select * from preferences where domain = 'loginwindow'; select preferences.* from users join preferences using (username);`

## 7. Logs & Crashes
macOS Unified Logging (`unified_log`), Apple System Log (`asl`), application/system crash reports (`crashes`), and kernel panic logs (`kernel_panics`).

### `unified_log` (`darwin/unified_log.table`)
Queries the OSLog framework for entries in the system log. The maximum number of rows returned is limited for performance issues. Use timestamp > or >= constraints to optimize query performance. This table introduces a new idiom for extracting sequential data in batches using multiple queries, ordered by timestamp. To trigger it, the user should include the condition "timestamp > -1", and the table will handle pagination. Note that the saved pagination counter is incremented globally across all queries and table invocations within a query. To avoid multiple table invocations within a query, use only AND and = constraints in WHERE clause.
- `timestamp` (BIGINT, ADDITIONAL): unix timestamp associated with the entry
- `timestamp_double` (TEXT): floating point timestamp associated with the entry
- `storage` (INTEGER, ADDITIONAL): the storage category for the entry
- `message` (TEXT, ADDITIONAL): composed message
- `activity` (BIGINT, ADDITIONAL): the activity ID associate with the entry
- `process` (TEXT, ADDITIONAL): the name of the process that made the entry
- `pid` (BIGINT, ADDITIONAL): the pid of the process that made the entry
- `sender` (TEXT, ADDITIONAL): the name of the binary image that made the entry
- `tid` (BIGINT, ADDITIONAL): the tid of the thread that made the entry
- `category` (TEXT, ADDITIONAL): the category of the os_log_t used
- `subsystem` (TEXT, ADDITIONAL): the subsystem of the os_log_t used
- `level` (TEXT, ADDITIONAL): the severity level of the entry (undefined, debug, info, default, error, fault)
- `max_rows` (INTEGER, ADDITIONAL, HIDDEN): the max number of rows returned (defaults to 100)
- `predicate` (TEXT, ADDITIONAL, HIDDEN): predicate to search (see `log help predicates`), note that this is merged into the predicate created from the column constraints
- *Example*: `select * from unified_log where timestamp > unixepoch('now', '-2 hours'); select * from unified_log where process = 'osqueryd' AND timestamp > unixepoch('now', '-2 hours');`

### `asl` (`darwin/asl.table`)
Queries the Apple System Log data structure for system events.
- `time` (INTEGER, ADDITIONAL): Unix timestamp.  Set automatically
- `time_nano_sec` (INTEGER, ADDITIONAL): Nanosecond time.
- `host` (TEXT, ADDITIONAL): Sender's address (set by the server).
- `sender` (TEXT, ADDITIONAL): Sender's identification string.  Default is process name.
- `facility` (TEXT, ADDITIONAL): Sender's facility.  Default is 'user'.
- `pid` (INTEGER, ADDITIONAL): Sending process ID encoded as a string.  Set automatically.
- `gid` (BIGINT, ADDITIONAL): GID that sent the log message (set by the server).
- `uid` (BIGINT, ADDITIONAL): UID that sent the log message (set by the server).
- `level` (INTEGER, ADDITIONAL): Log level number.  See levels in asl.h.
- `message` (TEXT, ADDITIONAL): Message text.
- `ref_pid` (INTEGER, ADDITIONAL): Reference PID for messages proxied by launchd
- `ref_proc` (TEXT, ADDITIONAL): Reference process for messages proxied by launchd
- `extra` (TEXT): Extra columns, in JSON format. Queries against this column are performed entirely in SQLite, so do not benefit from efficient querying via asl.h.

### `crashes` (`darwin/crashes.table` | joins with `users`)
Application, System, and Mobile App crash logs.
- `type` (TEXT): Type of crash log
- `pid` (BIGINT): Process (or thread) ID of the crashed process
- `path` (TEXT): Path to the crashed process
- `crash_path` (TEXT, INDEXED): Location of log file
- `identifier` (TEXT): Identifier of the crashed process
- `version` (TEXT): Version info of the crashed process
- `parent` (BIGINT): Parent PID of the crashed process
- `responsible` (TEXT): Process responsible for the crashed process
- `uid` (INTEGER, INDEXED): User ID of the crashed process
- `datetime` (TEXT): Date/Time at which the crash occurred
- `crashed_thread` (BIGINT): Thread ID which crashed
- `stack_trace` (TEXT): Most recent frame from the stack trace
- `exception_type` (TEXT): Exception type of the crash
- `exception_codes` (TEXT): Exception codes from the crash
- `exception_notes` (TEXT): Exception notes from the crash
- `registers` (TEXT): The value of the system registers
- *Example*: `select * from users join crashes using (uid);`

### `kernel_panics` (`darwin/kernel_panics.table`)
System kernel panic logs.
- `path` (TEXT): Location of log file
- `time` (TEXT): Formatted time of the event
- `registers` (TEXT): A space delimited line of register:value pairs
- `frame_backtrace` (TEXT): Backtrace of the crashed module
- `module_backtrace` (TEXT): Modules appearing in the crashed module's backtrace
- `dependencies` (TEXT): Module dependencies existing in crashed module's backtrace
- `name` (TEXT): Process name corresponding to crashed thread
- `os_version` (TEXT): Version of the operating system
- `kernel_version` (TEXT): Version of the system kernel
- `system_model` (TEXT): Physical system model, for example 'MacBookPro12,1 (Mac-E43C1C25D4880AD6)'
- `uptime` (BIGINT): System uptime at kernel panic in nanoseconds
- `last_loaded` (TEXT): Last loaded module before panic
- `last_unloaded` (TEXT): Last unloaded module before panic

## 8. Packages, Homebrew, Apps & Containers
Installed macOS `.app` bundles (`apps`), Homebrew formulas/casks (`homebrew_packages`), MacPorts, `.pkg` receipts/history, browser/IDE extensions, Python/Node packages, and Docker containers/images/networks/volumes.

### `apps` (`darwin/apps.table`)
macOS applications installed in known search paths (e.g., /Applications).
- `name` (TEXT): Name of the Name.app folder
- `path` (TEXT, INDEXED): Absolute and full Name.app path
- `bundle_executable` (TEXT): Info properties CFBundleExecutable label
- `bundle_identifier` (TEXT): Info properties CFBundleIdentifier label
- `bundle_name` (TEXT): Info properties CFBundleName label
- `bundle_short_version` (TEXT): Info properties CFBundleShortVersionString label
- `bundle_version` (TEXT): Info properties CFBundleVersion label
- `bundle_package_type` (TEXT): Info properties CFBundlePackageType label
- `environment` (TEXT): Application-set environment variables
- `element` (TEXT): Does the app identify as a background agent
- `compiler` (TEXT): Info properties DTCompiler label
- `development_region` (TEXT): Info properties CFBundleDevelopmentRegion label
- `display_name` (TEXT): Info properties CFBundleDisplayName label
- `info_string` (TEXT): Info properties CFBundleGetInfoString label
- `minimum_system_version` (TEXT): Minimum version of macOS required for the app to run
- `category` (TEXT): The UTI that categorizes the app for the App Store
- `applescript_enabled` (TEXT): Info properties NSAppleScriptEnabled label
- `copyright` (TEXT): Info properties NSHumanReadableCopyright label
- `last_opened_time` (DOUBLE): The time that the app was last used

### `app_schemes` (`darwin/app_schemes.table`)
macOS application schemes and handlers (e.g., http, file, mailto).
- `scheme` (TEXT): Name of the scheme/protocol
- `handler` (TEXT): Application label for the handler
- `enabled` (INTEGER): 1 if this handler is the OS default, else 0
- `external` (INTEGER): 1 if this handler does NOT exist on macOS by default, else 0
- `protected` (INTEGER): 1 if this handler is protected (reserved) by macOS, else 0

### `homebrew_packages` (`posix/homebrew_packages.table`)
The installed homebrew package database.
- `name` (TEXT): Package name
- `path` (TEXT): Package install path
- `version` (TEXT): Current 'linked' version
- `type` (TEXT): Package type ('formula' or 'cask')
- `auto_updates` (INTEGER): 1 if the cask auto-updates otherwise 0
- `app_name` (TEXT): Name of the installed App (for Casks)
- `prefix` (TEXT, INDEXED, ADDITIONAL, HIDDEN): Homebrew install prefix

### `package_receipts` (`darwin/package_receipts.table` | aliases: `packages`)
macOS package receipt details.
- `package_id` (TEXT): Package domain identifier
- `package_filename` (TEXT, INDEXED, HIDDEN): Filename of original .pkg file
- `version` (TEXT): Installed package version
- `location` (TEXT): Optional relative install path on volume
- `install_time` (DOUBLE): Timestamp of install time
- `installer_name` (TEXT): Name of installer process
- `path` (TEXT, ADDITIONAL): Path of receipt plist
- *Example*: `SELECT * FROM package_receipts;`

### `package_install_history` (`darwin/package_install_history.table`)
macOS package install history.
- `package_id` (TEXT): Label packageIdentifiers
- `time` (INTEGER): Label date as UNIX timestamp
- `name` (TEXT): Package display name
- `version` (TEXT): Package display version
- `source` (TEXT): Install source: usually the installer process name
- `content_type` (TEXT): Package content_type (optional)

### `package_bom` (`darwin/package_bom.table`)
macOS package bill of materials (BOM) file list.
- **Required `WHERE` constraint**: `path`
- `filepath` (TEXT): Package file or directory
- `uid` (INTEGER): Expected user of file or directory
- `gid` (INTEGER): Expected group of file or directory
- `mode` (INTEGER): Expected permissions
- `size` (BIGINT): Expected file size
- `modified_time` (INTEGER): Timestamp the file was installed
- `path` (TEXT, REQUIRED): Path of package bom
- *Example*: `select * from package_bom where path = '/var/db/receipts/com.apple.pkg.MobileDevice.bom';`

### `browser_plugins` (`darwin/browser_plugins.table` | joins with `users`)
All C/NPAPI browser plugin details for all users. C/NPAPI has been deprecated on all major browsers. To query for plugins on modern browsers, try: `chrome_extensions` `firefox_addons` `safari_extensions`.
- `uid` (BIGINT, INDEXED): The local user that owns the plugin
- `name` (TEXT): Plugin display name
- `identifier` (TEXT): Plugin identifier
- `version` (TEXT): Plugin short version
- `sdk` (TEXT): Build SDK used to compile plugin
- `description` (TEXT): Plugin description text
- `development_region` (TEXT): Plugin language-localization
- `native` (INTEGER): Plugin requires native execution
- `path` (TEXT, INDEXED): Path to plugin bundle
- `disabled` (INTEGER): Is the plugin disabled. 1 = Disabled
- *Example*: `select * from users join browser_plugins using (uid);`

### `chrome_extensions` (`chrome_extensions.table` | joins with `users`)
Chrome-based browser extensions.
- `browser_type` (TEXT): The browser type (Valid values: chrome, chrome_beta, chrome_dev, chrome_canary, chromium, opera, yandex, brave, brave_beta, brave_nightly, edge, edge_beta, edge_dev, edge_canary, vivaldi, arc, dia, comet)
- `uid` (BIGINT, INDEXED): The local user that owns the extension
- `name` (TEXT): Extension display name
- `profile` (TEXT): The name of the Chrome profile that contains this extension
- `profile_path` (TEXT): The profile path
- `referenced_identifier` (TEXT): Extension identifier, as specified by the preferences file. Empty if the extension is not in the profile.
- `identifier` (TEXT): Extension identifier, computed from its manifest. Empty in case of error.
- `version` (TEXT): Extension-supplied version
- `description` (TEXT): Extension-optional description
- `default_locale` (TEXT, alias:locale): Default locale supported by extension
- `current_locale` (TEXT): Current locale supported by extension
- `update_url` (TEXT): Extension-supplied update URI
- `author` (TEXT): Optional extension author
- `persistent` (INTEGER): 1 If extension is persistent across all tabs else 0
- `path` (TEXT): Path to extension folder
- `permissions` (TEXT): The permissions required by the extension
- `permissions_json` (TEXT, HIDDEN): The JSON-encoded permissions required by the extension
- `optional_permissions` (TEXT): The permissions optionally required by the extensions
- `optional_permissions_json` (TEXT, HIDDEN): The JSON-encoded permissions optionally required by the extensions
- `manifest_hash` (TEXT): The SHA256 hash of the manifest.json file
- `referenced` (BIGINT): 1 if this extension is referenced by the Preferences file of the profile
- `from_webstore` (TEXT): True if this extension was installed from the web store
- `state` (TEXT): 1 if this extension is enabled
- `install_time` (TEXT): Extension install time, in its original Webkit format
- `install_timestamp` (BIGINT): Extension install time, converted to unix time
- `manifest_json` (TEXT, HIDDEN): The manifest file of the extension
- `key` (TEXT, HIDDEN): The extension key, from the manifest file
- *Example*: `select * from users join chrome_extensions using (uid);`

### `chrome_extension_content_scripts` (`chrome_extension_content_scripts.table` | joins with `users`)
Chrome browser extension content scripts.
- `browser_type` (TEXT): The browser type (Valid values: chrome, chromium, opera, yandex, brave)
- `uid` (BIGINT, INDEXED): The local user that owns the extension
- `identifier` (TEXT): Extension identifier
- `version` (TEXT): Extension-supplied version
- `script` (TEXT): The content script used by the extension
- `match` (TEXT): The pattern that the script is matched against
- `profile_path` (TEXT): The profile path
- `path` (TEXT): Path to extension folder
- `referenced` (BIGINT): 1 if this extension is referenced by the Preferences file of the profile
- *Example*: `SELECT chrome_extension_content_scripts.* FROM users JOIN chrome_extension_content_scripts USING (uid) GROUP BY identifier, match;`

### `firefox_addons` (`firefox_addons.table` | joins with `users`)
Firefox browser extensions, webapps, and addons.
- `uid` (BIGINT, INDEXED, ADDITIONAL): The local user that owns the addon
- `name` (TEXT): Addon display name
- `identifier` (TEXT, INDEXED): Addon identifier
- `creator` (TEXT): Addon-supported creator string
- `type` (TEXT): Extension, addon, webapp
- `version` (TEXT): Addon-supplied version string
- `description` (TEXT): Addon-supplied description string
- `source_url` (TEXT): URL that installed the addon
- `visible` (INTEGER): 1 If the addon is shown in browser else 0
- `active` (INTEGER): 1 If the addon is active else 0
- `disabled` (INTEGER): 1 If the addon is application-disabled else 0
- `autoupdate` (INTEGER): 1 If the addon applies background updates else 0
- `location` (TEXT): Global, profile location
- `path` (TEXT): Path to plugin bundle
- *Example*: `SELECT * FROM users CROSS JOIN firefox_addons USING (uid);`

### `safari_extensions` (`darwin/safari_extensions.table` | joins with `users`)
Safari browser extension details for all users. This table requires Full Disk Access (FDA) permission.
- `uid` (BIGINT, INDEXED): The local user that owns the extension
- `name` (TEXT): Extension display name
- `identifier` (TEXT): Extension identifier
- `version` (TEXT): Extension long version
- `sdk` (TEXT): Bundle SDK used to compile extension
- `description` (TEXT): Optional extension description text
- `path` (TEXT): Path to the Info.plist describing the extension
- `bundle_version` (TEXT): The version of the build that identifies an iteration of the bundle
- `copyright` (TEXT): A human-readable copyright notice for the bundle
- *Example*: `select * from safari_extensions where uid=501; select count(*) from users JOIN safari_extensions using (uid);`

### `vscode_extensions` (`vscode_extensions.table` | joins with `users`)
Lists all vscode extensions.
- `name` (TEXT): Extension Name
- `uuid` (TEXT): Extension UUID
- `version` (TEXT): Extension version
- `path` (TEXT): Extension path
- `publisher` (TEXT): Publisher Name
- `publisher_id` (TEXT): Publisher ID
- `installed_at` (BIGINT): Installed Timestamp
- `prerelease` (INTEGER): Pre release version
- `uid` (BIGINT, INDEXED, ADDITIONAL): The local user that owns the plugin
- `vscode_edition` (TEXT): The VSCode edition (vscode, vscode_insiders, vscodium, vscodium_insiders, cursor, windsurf, trae)
- *Example*: `select * from vscode_extensions;`

### `jetbrains_plugins` (`jetbrains_plugins.table` | joins with `users`)
JetBrains IDEs plugins.
- `product_type` (TEXT): The product type (Valid values: CLion, DataGrip, GoLand, IntelliJIdea, IntelliJIdeaCommunityEdition, PhpStorm, PyCharm, PyCharmCommunityEdition, ReSharper, Rider, RubyMine, RustRover, WebStorm)
- `uid` (BIGINT, INDEXED): The local user that owns the plugin
- `name` (TEXT): Name of the plugin (Title Case)
- `version` (TEXT): Version of the plugin
- `vendor` (TEXT): The vendor name or organization id that authored the plugin
- `path` (TEXT): The path on the filesystem for the plugin. This may be a folder or a jar filename
- *Example*: `select * from users cross join jetbrains_plugins using (uid);`

### `python_packages` (`python_packages.table` | joins with `users`)
Python packages installed in a system. NOTE: when querying on windows, even without a users cross join, all user installed python packages will be returned. This special behavior is to not break original functionality.
- `name` (TEXT): Package display name
- `uid` (BIGINT, INDEXED): The local user that owns the python package
- `version` (TEXT): Package-supplied version
- `summary` (TEXT): Package-supplied summary
- `author` (TEXT): Optional package author
- `license` (TEXT): License under which package is launched
- `path` (TEXT): Path at which this module resides
- `directory` (TEXT, INDEXED): Directory where Python modules are located
- *Example*: `select * from python_packages where directory='/usr/'; select * from users cross join python_packages using (uid);`

### `npm_packages` (`npm_packages.table`)
Node packages installed in a system.
- `name` (TEXT): Package display name
- `version` (TEXT): Package-supplied version
- `description` (TEXT): Package-supplied description
- `author` (TEXT): Package-supplied author
- `license` (TEXT): License under which package is launched
- `homepage` (TEXT): Package supplied homepage
- `path` (TEXT): Path at which this module resides
- `directory` (TEXT, INDEXED): Directory where node_modules are located
- `depth` (INTEGER): Nesting depth of the package (0 = direct dependency)
- `max_depth` (INTEGER, ADDITIONAL, HIDDEN): Maximum depth to search for nested packages (default 100, -1 = unlimited)
- *Example*: `select * from npm_packages; select * from npm_packages where directory = '/home/user/my_project';`

### `docker_info` (`posix/docker_info.table`)
Docker system information.
- `id` (TEXT): Docker system ID
- `containers` (INTEGER): Total number of containers
- `containers_running` (INTEGER): Number of containers currently running
- `containers_paused` (INTEGER): Number of containers in paused state
- `containers_stopped` (INTEGER): Number of containers in stopped state
- `images` (INTEGER): Number of images
- `storage_driver` (TEXT): Storage driver
- `memory_limit` (INTEGER): 1 if memory limit support is enabled. 0 otherwise
- `swap_limit` (INTEGER): 1 if swap limit support is enabled. 0 otherwise
- `kernel_memory` (INTEGER): 1 if kernel memory limit support is enabled. 0 otherwise
- `cpu_cfs_period` (INTEGER): 1 if CPU Completely Fair Scheduler (CFS) period support is enabled. 0 otherwise
- `cpu_cfs_quota` (INTEGER): 1 if CPU Completely Fair Scheduler (CFS) quota support is enabled. 0 otherwise
- `cpu_shares` (INTEGER): 1 if CPU share weighting support is enabled. 0 otherwise
- `cpu_set` (INTEGER): 1 if CPU set selection support is enabled. 0 otherwise
- `ipv4_forwarding` (INTEGER): 1 if IPv4 forwarding is enabled. 0 otherwise
- `bridge_nf_iptables` (INTEGER): 1 if bridge netfilter iptables is enabled. 0 otherwise
- `bridge_nf_ip6tables` (INTEGER): 1 if bridge netfilter ip6tables is enabled. 0 otherwise
- `oom_kill_disable` (INTEGER): 1 if Out-of-memory kill is disabled. 0 otherwise
- `logging_driver` (TEXT): Logging driver
- `cgroup_driver` (TEXT): Control groups driver
- `kernel_version` (TEXT): Kernel version
- `os` (TEXT): Operating system
- `os_type` (TEXT): Operating system type
- `architecture` (TEXT): Hardware architecture
- `cpus` (INTEGER): Number of CPUs
- `memory` (BIGINT): Total memory
- `http_proxy` (TEXT): HTTP proxy
- `https_proxy` (TEXT): HTTPS proxy
- `no_proxy` (TEXT): Comma-separated list of domain extensions proxy should not be used for
- `name` (TEXT): Name of the docker host
- `server_version` (TEXT): Server version
- `root_dir` (TEXT): Docker root directory
- *Example*: `select * from docker_info;`

### `docker_version` (`posix/docker_version.table`)
Docker version information.
- `version` (TEXT): Docker version
- `api_version` (TEXT): API version
- `min_api_version` (TEXT): Minimum API version supported
- `git_commit` (TEXT): Docker build git commit
- `go_version` (TEXT): Go version
- `os` (TEXT): Operating system
- `arch` (TEXT): Hardware architecture
- `kernel_version` (TEXT): Kernel version
- `build_time` (TEXT): Build time
- *Example*: `select version from docker_version;`

### `docker_containers` (`posix/docker_containers.table`)
Docker containers information.
- `id` (TEXT, INDEXED): Container ID
- `name` (TEXT, INDEXED): Container name
- `image` (TEXT): Docker image (name) used to launch this container
- `image_id` (TEXT): Docker image ID
- `command` (TEXT): Command with arguments
- `created` (BIGINT): Time of creation as UNIX time
- `state` (TEXT): Container state (created, restarting, running, removing, paused, exited, dead)
- `status` (TEXT): Container status information
- `pid` (BIGINT): Identifier of the initial process
- `path` (TEXT): Container path
- `config_entrypoint` (TEXT): Container entrypoint(s)
- `started_at` (TEXT): Container start time as string
- `finished_at` (TEXT): Container finish time as string
- `privileged` (INTEGER): Is the container privileged
- `security_options` (TEXT): List of container security options
- `env_variables` (TEXT): Container environmental variables
- `readonly_rootfs` (INTEGER): Is the root filesystem mounted as read only
- *Example*: `select * from docker_containers where name = '/hello';`

### `docker_container_processes` (`posix/docker_container_processes.table`)
Docker container processes.
- **Required `WHERE` constraint**: `id`
- `id` (TEXT, REQUIRED): Container ID
- `pid` (BIGINT, INDEXED): Process ID
- `name` (TEXT): The process path or shorthand argv[0]
- `cmdline` (TEXT): Complete argv
- `state` (TEXT): Process state
- `uid` (BIGINT): User ID
- `gid` (BIGINT): Group ID
- `euid` (BIGINT): Effective user ID
- `egid` (BIGINT): Effective group ID
- `suid` (BIGINT): Saved user ID
- `sgid` (BIGINT): Saved group ID
- `wired_size` (BIGINT): Bytes of unpageable memory used by process
- `resident_size` (BIGINT): Bytes of private memory used by process
- `total_size` (BIGINT): Total virtual memory size
- `start_time` (BIGINT): Process start in seconds since boot (non-sleeping)
- `parent` (BIGINT): Process parent's PID
- `pgroup` (BIGINT): Process group
- `threads` (INTEGER): Number of threads used by process
- `nice` (INTEGER): Process nice level (-20 to 20, default 0)
- `user` (TEXT): User name
- `time` (TEXT): Cumulative CPU time. [DD-]HH:MM:SS format
- `cpu` (DOUBLE): CPU utilization as percentage
- `mem` (DOUBLE): Memory utilization as percentage
- *Example*: `select * from docker_container_processes where id = '1234567890abcdef';`

### `docker_container_stats` (`posix/docker_container_stats.table`)
Docker container statistics. Queries on this table take at least one second.
- **Required `WHERE` constraint**: `id`
- `id` (TEXT, REQUIRED): Container ID
- `name` (TEXT, INDEXED): Container name
- `pids` (INTEGER): Number of processes
- `read` (BIGINT): UNIX time when stats were read
- `preread` (BIGINT): UNIX time when stats were last read
- `interval` (BIGINT): Difference between read and preread in nano-seconds
- `disk_read` (BIGINT): Total disk read bytes
- `disk_write` (BIGINT): Total disk write bytes
- `num_procs` (INTEGER): Number of processors
- `cpu_total_usage` (BIGINT): Total CPU usage
- `cpu_kernelmode_usage` (BIGINT): CPU kernel mode usage
- `cpu_usermode_usage` (BIGINT): CPU user mode usage
- `system_cpu_usage` (BIGINT): CPU system usage
- `online_cpus` (INTEGER): Online CPUs
- `pre_cpu_total_usage` (BIGINT): Last read total CPU usage
- `pre_cpu_kernelmode_usage` (BIGINT): Last read CPU kernel mode usage
- `pre_cpu_usermode_usage` (BIGINT): Last read CPU user mode usage
- `pre_system_cpu_usage` (BIGINT): Last read CPU system usage
- `pre_online_cpus` (INTEGER): Last read online CPUs
- `memory_usage` (BIGINT): Memory usage
- `memory_cached` (BIGINT): Memory cached
- `memory_inactive_file` (BIGINT): Memory inactive file
- `memory_total_inactive_file` (BIGINT): Memory total inactive file
- `memory_max_usage` (BIGINT): Memory maximum usage
- `memory_limit` (BIGINT): Memory limit
- `network_rx_bytes` (BIGINT): Total network bytes read
- `network_tx_bytes` (BIGINT): Total network bytes transmitted
- *Example*: `select * from docker_container_stats where id = 'de8cfdc74c850967';`

### `docker_container_ports` (`posix/docker_container_ports.table`)
Docker container ports.
- `id` (TEXT, ADDITIONAL): Container ID
- `type` (TEXT): Protocol (tcp, udp)
- `port` (INTEGER): Port inside the container
- `host_ip` (TEXT): Host IP address on which public port is listening
- `host_port` (INTEGER): Host port
- *Example*: `select * from docker_container_ports; select * from docker_container_ports where id = '1234567890abcdef';`

### `docker_container_mounts` (`posix/docker_container_mounts.table`)
Docker container mounts.
- `id` (TEXT, INDEXED): Container ID
- `type` (TEXT): Type of mount (bind, volume)
- `name` (TEXT, INDEXED): Optional mount name
- `source` (TEXT): Source path on host
- `destination` (TEXT): Destination path inside container
- `driver` (TEXT): Driver providing the mount
- `mode` (TEXT): Mount options (rw, ro)
- `rw` (INTEGER): 1 if read/write. 0 otherwise
- `propagation` (TEXT): Mount propagation
- *Example*: `select * from docker_container_mounts; select * from docker_container_mounts where id = '1234567890abcdef';`

### `docker_container_networks` (`posix/docker_container_networks.table`)
Docker container networks.
- `id` (TEXT, INDEXED): Container ID
- `name` (TEXT, INDEXED): Network name
- `network_id` (TEXT): Network ID
- `endpoint_id` (TEXT): Endpoint ID
- `gateway` (TEXT): Gateway
- `ip_address` (TEXT): IP address
- `ip_prefix_len` (INTEGER): IP subnet prefix length
- `ipv6_gateway` (TEXT): IPv6 gateway
- `ipv6_address` (TEXT): IPv6 address
- `ipv6_prefix_len` (INTEGER): IPv6 subnet prefix length
- `mac_address` (TEXT): MAC address
- *Example*: `select * from docker_container_networks; select * from docker_container_networks where id = '1234567890abcdef';`

### `docker_container_envs` (`posix/docker_container_envs.table`)
Docker container environment variables.
- `id` (TEXT, INDEXED): Container ID
- `key` (TEXT): Environment variable name
- `value` (TEXT): Environment variable value
- *Example*: `select * from docker_container_envs; select * from docker_container_envs where id = '1234567890abcdef';`

### `docker_container_labels` (`posix/docker_container_labels.table`)
Docker container labels.
- `id` (TEXT, INDEXED): Container ID
- `key` (TEXT, INDEXED): Label key
- `value` (TEXT): Optional label value
- *Example*: `select * from docker_container_labels; select * from docker_container_labels where id = '1234567890abcdef';`

### `docker_container_fs_changes` (`posix/docker_container_fs_changes.table`)
Changes to files or directories on container's filesystem.
- **Required `WHERE` constraint**: `id`
- `id` (TEXT, REQUIRED): Container ID
- `path` (TEXT): FIle or directory path relative to rootfs
- `change_type` (TEXT): Type of change: C:Modified, A:Added, D:Deleted
- *Example*: `select * from docker_container_fs_changes where id = '1234567890abcdef';`

### `docker_images` (`posix/docker_images.table`)
Docker images information.
- `id` (TEXT): Image ID
- `created` (BIGINT): Time of creation as UNIX time
- `size_bytes` (BIGINT): Size of image in bytes
- `tags` (TEXT): Comma-separated list of repository tags
- *Example*: `select * from docker_images; select * from docker_images where id = '6a2f32de169d';`

### `docker_image_layers` (`posix/docker_image_layers.table`)
Docker image layers information.
- `id` (TEXT, INDEXED): Image ID
- `layer_id` (TEXT): Layer ID
- `layer_order` (INTEGER): Layer Order (1 = base layer)
- *Example*: `select * from docker_image_layers; select * from docker_image_layers where id = '6a2f32de169d';`

### `docker_image_history` (`posix/docker_image_history.table`)
Docker image history information.
- `id` (TEXT, INDEXED): Image ID
- `created` (BIGINT): Time of creation as UNIX time
- `size` (BIGINT): Size of instruction in bytes
- `created_by` (TEXT): Created by instruction
- `tags` (TEXT): Comma-separated list of tags
- `comment` (TEXT): Instruction comment
- *Example*: `select * from docker_image_history; select * from docker_image_history where id = '6a2f32de169d';`

### `docker_image_labels` (`posix/docker_image_labels.table`)
Docker image labels.
- `id` (TEXT, INDEXED): Image ID
- `key` (TEXT): Label key
- `value` (TEXT): Optional label value
- *Example*: `select * from docker_image_labels; select * from docker_image_labels where id = '1234567890abcdef';`

### `docker_networks` (`posix/docker_networks.table`)
Docker networks information.
- `id` (TEXT, INDEXED): Network ID
- `name` (TEXT): Network name
- `driver` (TEXT): Network driver
- `created` (BIGINT): Time of creation as UNIX time
- `enable_ipv6` (INTEGER): 1 if IPv6 is enabled on this network. 0 otherwise
- `subnet` (TEXT): Network subnet
- `gateway` (TEXT): Network gateway
- *Example*: `select * from docker_networks; select * from docker_networks where id = 'cfd2ffd49439';`

### `docker_network_labels` (`posix/docker_network_labels.table`)
Docker network labels.
- `id` (TEXT, INDEXED): Network ID
- `key` (TEXT): Label key
- `value` (TEXT): Optional label value
- *Example*: `select * from docker_network_labels; select * from docker_network_labels where id = '1234567890abcdef';`

### `docker_volumes` (`posix/docker_volumes.table`)
Docker volumes information.
- `name` (TEXT, INDEXED): Volume name
- `driver` (TEXT): Volume driver
- `mount_point` (TEXT): Mount point
- `type` (TEXT): Volume type
- *Example*: `select * from docker_volumes; select * from docker_volumes where name = 'btrfs';`

### `docker_volume_labels` (`posix/docker_volume_labels.table`)
Docker volume labels.
- `name` (TEXT, INDEXED): Volume name
- `key` (TEXT, INDEXED): Label key
- `value` (TEXT): Optional label value
- *Example*: `select * from docker_volume_labels; select * from docker_volume_labels where name = 'btrfs';`
