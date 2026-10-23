---
name: linux
description: Complete Linux osquery table catalog (159 tables) and schemas for diagnosing Linux operating system issues, including memory_info, processes, systemd_units, kernel_info, kernel_modules, mounts, block_devices, md_devices, md_drives, iptables, listening_ports, process_open_sockets, deb_packages, rpm_packages, syslog_events, Docker/LXD containers, and security/audit tables.
license: Apache-2.0
---

# Linux osquery Diagnostic Skill (`linux`)

> *Table schemas and descriptions adapted from [osquery](https://github.com/osquery/osquery) specifications (licensed under Apache-2.0).*

This skill provides the complete, authoritative reference of all **159 osquery tables** supported on **Linux** (`specs/*.table`, `specs/utility/*.table`, `specs/posix/*.table`, `specs/linux/*.table`, `specs/linwin/*.table`, and `specs/sleuthkit/*.table`), including full column schemas, types, descriptions, table aliases, and required `WHERE` clause constraints.

---

## 1. Critical Linux Diagnostic Guidance

### 1.1 `memory_info` IS Populated and Authoritative on Linux
Unlike macOS (where `virtual_memory_info` is used), **`memory_info` is a native Linux table** (`specs/linux/memory_info.table`) backed directly by `/proc/meminfo`. Always query `memory_info` first when diagnosing Linux RAM, page cache, buffer, or swap pressure:

```sql
SELECT
  memory_total,
  memory_free,
  memory_available,
  buffers,
  cached,
  swap_cached,
  active,
  inactive,
  swap_total,
  swap_free
FROM memory_info;
```

- All columns in `memory_info` are reported in **bytes** (`BIGINT`).
- Use `memory_available` (not just `memory_free`) to determine how much memory is available for starting new applications without swapping, because Linux aggressively uses free RAM for `buffers` and `cached` pages.
- Swap pressure is indicated when `swap_free < swap_total` and `memory_available` is low relative to `memory_total`.

### 1.2 Primary Linux Diagnostic Tables by Symptom

| Diagnostic Domain | Key Linux Tables |
|---|---|
| **Memory & Swap Pressure** | `memory_info`, `processes` (`resident_size`, `total_size`, `wired_size`, `cgroup_path`), `process_memory_map`, `shared_memory`, `memory_map`, `memory_devices`, `memory_error_info` |
| **CPU & System Load** | `load_average`, `cpu_time`, `cpu_info`, `cpuid`, `processes` (`user_time`, `system_time`, `threads`, `nice`, `state`), `msr` |
| **Systemd & Services** | `systemd_units` (`id`, `load_state`, `active_state`, `sub_state`, `unit_file_state`, `fragment_path`), `startup_items`, `crontab` |
| **Kernel, Boot & Modules** | `kernel_info`, `kernel_modules`, `kernel_keys`, `system_controls` (`sysctl`), `os_version`, `uptime`, `platform_info`, `secureboot`, `secureboot_certificates` |
| **Disks, Mounts & RAID** | `mounts`, `block_devices`, `disk_encryption`, `md_devices`, `md_drives`, `md_personalities`, `device_partitions`, `device_file`, `device_hash` |
| **Networking & Firewall** | `listening_ports`, `process_open_sockets`, `interface_addresses`, `interface_details`, `interface_ipv6`, `routes`, `arp_cache`, `dns_resolvers`, `etc_hosts`, `iptables`, `curl`, `curl_certificate` |
| **Packages & Repositories** | `deb_packages`, `deb_package_files`, `apt_sources`, `rpm_packages`, `rpm_package_files`, `yum_sources`, `pacman_packages`, `snap_packages`, `portage_packages`, `homebrew_packages`, `python_packages`, `npm_packages` |
| **Users, Auth & Privilege** | `users`, `groups`, `user_groups`, `logged_in_users`, `last`, `shadow`, `sudoers`, `suid_bin`, `authorized_keys`, `known_hosts`, `user_ssh_keys`, `ssh_configs`, `shell_history` |
| **MAC Security & Auditing** | `apparmor_profiles`, `apparmor_events`, `selinux_settings`, `selinux_events`, `seccomp_events`, `syslog_events` (alias `syslog`), `process_events`, `process_file_events`, `socket_events`, `file_events`, `user_events`, `yara_file` (alias `yara`), `yara_process` |
| **Containers (Docker / LXD)** | `process_namespaces`, `docker_info`, `docker_containers`, `docker_container_stats`, `docker_container_processes`, `docker_container_mounts`, `docker_container_ports`, `lxd_instances`, `lxd_instance_config`, `lxd_storage_pools` |

### 1.3 Tables Requiring Mandatory `WHERE` Constraints (`required=True`)
Never run an unqualified `SELECT *` on the following tables without providing their required `WHERE` predicate(s); osquery will reject or return zero rows without them:

| Table | Required `WHERE` Column(s) | Example Valid Query |
|---|---|---|
| `file` | `path` OR `directory` | `SELECT * FROM file WHERE path = '/etc/passwd';` or `WHERE directory = '/etc';` |
| `hash` | `path` OR `directory` | `SELECT * FROM hash WHERE path = '/usr/bin/sudo';` |
| `magic` | `path` | `SELECT * FROM magic WHERE path = '/bin/ls';` |
| `extended_attributes` | `path` OR `directory` | `SELECT * FROM extended_attributes WHERE path = '/usr/bin/ping';` |
| `yara_file` (alias `yara`) | `path` (plus `sig_group`, `sigfile`, `sigrule`, or `sigurl`) | `SELECT * FROM yara_file WHERE path = '/etc/passwd' AND sigrule = 'rule r { condition: true }';` |
| `yara_process` | `pid` (plus `sig_group`, `sigfile`, `sigrule`, or `sigurl`) | `SELECT * FROM yara_process WHERE pid = 1 AND sigrule = 'rule r { condition: true }';` |
| `curl` | `url` | `SELECT url, response_code, round_trip_time FROM curl WHERE url = 'http://127.0.0.1:8080/health';` |
| `curl_certificate` | `hostname` | `SELECT common_name, valid_to, has_expired FROM curl_certificate WHERE hostname = 'example.com:443';` |
| `docker_container_fs_changes` | `id` | `SELECT * FROM docker_container_fs_changes WHERE id = '<container_id>';` |
| `docker_container_processes` | `id` | `SELECT * FROM docker_container_processes WHERE id = '<container_id>';` |
| `docker_container_stats` | `id` | `SELECT * FROM docker_container_stats WHERE id = '<container_id>';` |
| `lxd_instance_config` | `name` | `SELECT * FROM lxd_instance_config WHERE name = '<instance_name>';` |
| `lxd_instance_devices` | `name` | `SELECT * FROM lxd_instance_devices WHERE name = '<instance_name>';` |
| `device_partitions` | `device` | `SELECT * FROM device_partitions WHERE device = '/dev/sda';` |
| `device_file` | `device` AND `partition` | `SELECT * FROM device_file WHERE device = '/dev/sda' AND partition = '1';` |
| `device_hash` | `device` AND `partition` AND `inode` | `SELECT * FROM device_hash WHERE device = '/dev/sda' AND partition = '1' AND inode = 2;` |

### 1.4 User-Scoped Tables (`user_data=True`) Requiring `JOIN users USING (uid)` or `WHERE uid = ...`
The following 11 tables inspect per-user home directories and profiles. Always `JOIN users USING (uid)` or filter by `WHERE uid = <uid>` to enumerate across all local users:
- `authorized_keys`, `known_hosts`, `user_ssh_keys`, `ssh_configs`, `shell_history`
- `chrome_extensions`, `chrome_extension_content_scripts`, `firefox_addons`
- `vscode_extensions`, `jetbrains_plugins`, `python_packages`

### 1.5 Table Aliases on Linux
- `augeas` -> `configurations`
- `carbon_black_info` -> `cb_info`
- `etc_hosts` -> `hosts`
- `syslog_events` -> `syslog`
- `yara_file` -> `yara`

### 1.6 Container Namespace Introspection (`pid_with_namespace`)
On Linux, 19 tables support a hidden `additional=True` column `pid_with_namespace` (`INTEGER`) that allows querying inside a container/process mount or network namespace by specifying `WHERE pid_with_namespace = <pid>`:
`apt_sources`, `authorized_keys`, `crontab`, `deb_packages`, `dns_resolvers`, `etc_hosts`, `file`, `groups`, `hash`, `npm_packages`, `os_version`, `python_packages`, `rpm_packages`, `suid_bin`, `user_ssh_keys`, `users`, `yara_file`, `yara_process`, `yum_sources`.

---

## 2. Complete Linux Table & Schema Catalog (159 Tables)

Column flags legend:
- `REQUIRED`: Must be provided in a `WHERE` clause predicate.
- `ADDITIONAL`: Optional `WHERE` predicate parameter that changes or filters table generation behavior.
- `INDEX`: Indexed column for fast lookups/joins.
- `OPTIMIZED`: Query planner optimized column.
- `HIDDEN`: Omitted from `SELECT *` unless explicitly named in the `SELECT` list.
- `LINUX`: Linux/POSIX extended schema column (`extended_schema`).

---

### Category 1: System Identity, OS, Kernel & Boot (10 Tables)

#### `os_version`
- **Source**: `specs/os_version.table`
- **Description**: A single row containing the operating system name and version.
- **Columns**:
  - `name` (`TEXT`): Distribution or product name
  - `version` (`TEXT`): Pretty, suitable for presentation, OS version
  - `major` (`INTEGER`): Major release version
  - `minor` (`INTEGER`): Minor release version
  - `patch` (`INTEGER`): Optional patch release
  - `build` (`TEXT`): Optional build-specific or variant string
  - `platform` (`TEXT`): OS Platform or ID
  - `platform_like` (`TEXT`): Closely related platforms
  - `codename` (`TEXT`): OS version codename
  - `arch` (`TEXT`): OS Architecture
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace
  - `mount_namespace_id` (`TEXT`, `HIDDEN`, `LINUX`): Mount namespace id

#### `system_info`
- **Source**: `specs/system_info.table`
- **Description**: System information for identification.
- **Columns**:
  - `hostname` (`TEXT`): Network hostname including domain
  - `uuid` (`TEXT`): Unique ID provided by the system
  - `cpu_type` (`TEXT`): CPU type
  - `cpu_subtype` (`TEXT`): CPU subtype
  - `cpu_brand` (`TEXT`): CPU brand string, contains vendor and model
  - `cpu_physical_cores` (`INTEGER`): Number of physical CPU cores in to the system
  - `cpu_logical_cores` (`INTEGER`): Number of logical CPU cores available to the system
  - `cpu_sockets` (`INTEGER`): Number of processor sockets in the system
  - `cpu_microcode` (`TEXT`): Microcode version
  - `physical_memory` (`BIGINT`): Total physical memory in bytes
  - `hardware_vendor` (`TEXT`): Hardware vendor
  - `hardware_model` (`TEXT`): Hardware model
  - `hardware_version` (`TEXT`): Hardware version
  - `hardware_serial` (`TEXT`): Device serial number
  - `board_vendor` (`TEXT`): Board vendor
  - `board_model` (`TEXT`): Board model
  - `board_version` (`TEXT`): Board version
  - `board_serial` (`TEXT`): Board serial number
  - `computer_name` (`TEXT`): Friendly computer name (optional)
  - `local_hostname` (`TEXT`): Local hostname (optional)

#### `uptime`
- **Source**: `specs/uptime.table`
- **Description**: Track time passed since last boot. Some systems track this as calendar time, some as runtime.
- **Columns**:
  - `days` (`INTEGER`): Days of uptime
  - `hours` (`INTEGER`): Hours of uptime
  - `minutes` (`INTEGER`): Minutes of uptime
  - `seconds` (`INTEGER`): Seconds of uptime
  - `total_seconds` (`BIGINT`): Total uptime seconds

#### `kernel_info`
- **Source**: `specs/kernel_info.table`
- **Attributes**: `cacheable=True`
- **Description**: Basic active kernel information.
- **Columns**:
  - `version` (`TEXT`): Kernel version
  - `arguments` (`TEXT`): Kernel arguments
  - `path` (`TEXT`): Kernel path
  - `device` (`TEXT`): Kernel device identifier

#### `kernel_modules`
- **Source**: `specs/linux/kernel_modules.table`
- **Description**: Linux kernel modules both loaded and within the load search path.
- **Columns**:
  - `name` (`TEXT`): Module name
  - `size` (`BIGINT`): Size of module content
  - `used_by` (`TEXT`): Module reverse dependencies
  - `status` (`TEXT`): Kernel module status
  - `address` (`TEXT`): Kernel module address

#### `kernel_keys`
- **Source**: `specs/linux/kernel_keys.table`
- **Description**: List of security data, authentication keys and encryption keys.
- **Columns**:
  - `serial_number` (`TEXT`): The serial key of the key.
  - `flags` (`TEXT`): A set of flags describing the state of the key.
  - `usage` (`BIGINT`): the number of threads and open file references that refer to this key.
  - `timeout` (`TEXT`): The amount of time until the key will expire, expressed in human-readable form. The string perm here means that the key is permanent (no timeout). The string expd means that the key has already expired.
  - `permissions` (`TEXT`): The key permissions, expressed as four hexadecimal bytes containing, from left to right, the possessor, user, group, and other permissions.
  - `uid` (`BIGINT`): The user ID of the key owner.
  - `gid` (`BIGINT`): The group ID of the key.
  - `type` (`TEXT`): The key type.
  - `description` (`TEXT`): The key description.

#### `system_controls`
- **Source**: `specs/posix/system_controls.table`
- **Description**: sysctl names, values, and settings information.
- **Columns**:
  - `name` (`TEXT`, `INDEX`): Full sysctl MIB name
  - `oid` (`TEXT`, `ADDITIONAL`): Control MIB
  - `subsystem` (`TEXT`, `ADDITIONAL`): Subsystem ID, control type
  - `current_value` (`TEXT`): Value of setting
  - `config_value` (`TEXT`): The MIB value set in /etc/sysctl.conf
  - `type` (`TEXT`): Data type

#### `platform_info`
- **Source**: `specs/platform_info.table`
- **Description**: Information about EFI/UEFI/ROM and platform/boot.
- **Columns**:
  - `vendor` (`TEXT`): Platform code vendor
  - `version` (`TEXT`): Platform code version
  - `date` (`TEXT`): Self-reported platform code update date
  - `revision` (`TEXT`): BIOS major and minor revision
  - `extra` (`TEXT`): Platform-specific additional information
  - `firmware_type` (`TEXT`): The type of firmware (uefi, bios, iboot, openfirmware, unknown).
  - `address` (`TEXT`, `LINUX`): Relative address of firmware mapping
  - `size` (`TEXT`, `LINUX`): Size in bytes of firmware
  - `volume_size` (`INTEGER`, `LINUX`): (Optional) size of firmware volume

#### `secureboot`
- **Source**: `specs/secureboot.table`
- **Description**: Secure Boot UEFI Settings.
- **Columns**:
  - `secure_boot` (`INTEGER`): Whether secure boot is enabled
  - `setup_mode` (`INTEGER`, `LINUX`): Whether setup mode is enabled

#### `secureboot_certificates`
- **Source**: `specs/linux/secureboot_certificates.table`
- **Description**: X.509 certificates from UEFI Secure Boot signature databases (db and dbx EFI variables). Useful for monitoring CA expiry and adoption of updated certificates (e.g. Microsoft UEFI CA 2023).
- **Columns**:
  - `common_name` (`TEXT`): Certificate CommonName
  - `subject` (`TEXT`): Certificate subject distinguished name
  - `issuer` (`TEXT`): Certificate issuer distinguished name
  - `not_valid_before` (`DATETIME`): Lower bound of valid date
  - `not_valid_after` (`DATETIME`): Certificate expiration date
  - `sha1` (`TEXT`): SHA1 hash of the raw certificate contents
  - `serial` (`TEXT`): Certificate serial number
  - `revoked` (`INTEGER`): 1 if the certificate is in the dbx revocation list, 0 if it is in the db allowlist
  - `path` (`TEXT`): Path to the EFI variable file
  - `is_ca` (`INTEGER`): 1 if the certificate is a CA, 0 otherwise
  - `self_signed` (`INTEGER`): 1 if the certificate is self-signed, 0 otherwise
  - `key_usage` (`TEXT`): Certificate key usage extension string
  - `authority_key_id` (`TEXT`): Authority Key Identifier (AKI)
  - `subject_key_id` (`TEXT`): Subject Key Identifier (SKI)
  - `signing_algorithm` (`TEXT`): Algorithm used to sign the certificate
  - `key_algorithm` (`TEXT`): Public key algorithm
  - `key_strength` (`TEXT`): Public key size in bits

---

### Category 2: Memory & CPU Performance (12 Tables)

#### `memory_info`
- **Source**: `specs/linux/memory_info.table`
- **Description**: Main memory information in bytes.
- **Columns**:
  - `memory_total` (`BIGINT`): Total amount of physical RAM, in bytes
  - `memory_free` (`BIGINT`): The amount of physical RAM, in bytes, left unused by the system
  - `memory_available` (`BIGINT`): The amount of physical RAM, in bytes, available for starting new applications, without swapping
  - `buffers` (`BIGINT`): The amount of physical RAM, in bytes, used for file buffers
  - `cached` (`BIGINT`): The amount of physical RAM, in bytes, used as cache memory
  - `swap_cached` (`BIGINT`): The amount of swap, in bytes, used as cache memory
  - `active` (`BIGINT`): The total amount of buffer or page cache memory, in bytes, that is in active use
  - `inactive` (`BIGINT`): The total amount of buffer or page cache memory, in bytes, that are free and available
  - `swap_total` (`BIGINT`): The total amount of swap available, in bytes
  - `swap_free` (`BIGINT`): The total amount of swap free, in bytes

#### `memory_map`
- **Source**: `specs/linux/memory_map.table`
- **Description**: OS memory region map.
- **Columns**:
  - `name` (`TEXT`): Region name
  - `start` (`TEXT`): Start address of memory region
  - `end` (`TEXT`): End address of memory region

#### `shared_memory`
- **Source**: `specs/linux/shared_memory.table`
- **Description**: OS shared memory regions.
- **Columns**:
  - `shmid` (`INTEGER`): Shared memory segment ID
  - `owner_uid` (`BIGINT`): User ID of owning process
  - `creator_uid` (`BIGINT`): User ID of creator process
  - `pid` (`BIGINT`): Process ID to last use the segment
  - `creator_pid` (`BIGINT`): Process ID that created the segment
  - `atime` (`BIGINT`): Attached time
  - `dtime` (`BIGINT`): Detached time
  - `ctime` (`BIGINT`): Changed time
  - `permissions` (`TEXT`): Memory segment permissions
  - `size` (`BIGINT`): Size in bytes
  - `attached` (`INTEGER`): Number of attached processes
  - `status` (`TEXT`): Destination/attach status
  - `locked` (`INTEGER`): 1 if segment is locked else 0

#### `memory_devices`
- **Source**: `specs/memory_devices.table`
- **Description**: Physical memory device (type 17) information retrieved from SMBIOS.
- **Columns**:
  - `handle` (`TEXT`): Handle, or instance number, associated with the structure in SMBIOS
  - `array_handle` (`TEXT`): The memory array that the device is attached to
  - `form_factor` (`TEXT`): Implementation form factor for this memory device
  - `total_width` (`INTEGER`): Total width, in bits, of this memory device, including any check or error-correction bits
  - `data_width` (`INTEGER`): Data width, in bits, of this memory device
  - `size` (`INTEGER`): Size of memory device in Megabyte
  - `set` (`INTEGER`): Identifies if memory device is one of a set of devices. A value of 0 indicates no set affiliation.
  - `device_locator` (`TEXT`): String number of the string that identifies the physically-labeled socket or board position where the memory device is located
  - `bank_locator` (`TEXT`): String number of the string that identifies the physically-labeled bank where the memory device is located
  - `memory_type` (`TEXT`): Type of memory used
  - `memory_type_details` (`TEXT`): Additional details for memory device
  - `max_speed` (`INTEGER`): Max speed of memory device in megatransfers per second (MT/s)
  - `configured_clock_speed` (`INTEGER`): Configured speed of memory device in megatransfers per second (MT/s)
  - `manufacturer` (`TEXT`): Manufacturer ID string
  - `serial_number` (`TEXT`): Serial number of memory device
  - `asset_tag` (`TEXT`): Manufacturer specific asset tag of memory device
  - `part_number` (`TEXT`): Manufacturer specific serial number of memory device
  - `min_voltage` (`INTEGER`): Minimum operating voltage of device in millivolts
  - `max_voltage` (`INTEGER`): Maximum operating voltage of device in millivolts
  - `configured_voltage` (`INTEGER`): Configured operating voltage of device in millivolts

#### `memory_arrays`
- **Source**: `specs/posix/memory_arrays.table`
- **Description**: Data associated with collection of memory devices that operate to form a memory address.
- **Columns**:
  - `handle` (`TEXT`): Handle, or instance number, associated with the array
  - `location` (`TEXT`): Physical location of the memory array
  - `use` (`TEXT`): Function for which the array is used
  - `memory_error_correction` (`TEXT`): Primary hardware error correction or detection method supported
  - `max_capacity` (`INTEGER`): Maximum capacity of array in gigabytes
  - `memory_error_info_handle` (`TEXT`): Handle, or instance number, associated with any error that was detected for the array
  - `number_memory_devices` (`INTEGER`): Number of memory devices on array

#### `memory_array_mapped_addresses`
- **Source**: `specs/posix/memory_array_mapped_addresses.table`
- **Description**: Data associated for address mapping of physical memory arrays.
- **Columns**:
  - `handle` (`TEXT`): Handle, or instance number, associated with the structure
  - `memory_array_handle` (`TEXT`): Handle of the memory array associated with this structure
  - `starting_address` (`TEXT`): Physical stating address, in kilobytes, of a range of memory mapped to physical memory array
  - `ending_address` (`TEXT`): Physical ending address of last kilobyte of a range of memory mapped to physical memory array
  - `partition_width` (`INTEGER`): Number of memory devices that form a single row of memory for the address partition of this structure

#### `memory_device_mapped_addresses`
- **Source**: `specs/posix/memory_device_mapped_addresses.table`
- **Description**: Data associated for address mapping of physical memory devices.
- **Columns**:
  - `handle` (`TEXT`): Handle, or instance number, associated with the structure
  - `memory_device_handle` (`TEXT`): Handle of the memory device structure associated with this structure
  - `memory_array_mapped_address_handle` (`TEXT`): Handle of the memory array mapped address to which this device range is mapped to
  - `starting_address` (`TEXT`): Physical stating address, in kilobytes, of a range of memory mapped to physical memory array
  - `ending_address` (`TEXT`): Physical ending address of last kilobyte of a range of memory mapped to physical memory array
  - `partition_row_position` (`INTEGER`): Identifies the position of the referenced memory device in a row of the address partition
  - `interleave_position` (`INTEGER`): The position of the device in a interleave, i.e. 0 indicates non-interleave, 1 indicates 1st interleave, 2 indicates 2nd interleave, etc.
  - `interleave_data_depth` (`INTEGER`): The max number of consecutive rows from memory device that are accessed in a single interleave transfer; 0 indicates device is non-interleave

#### `memory_error_info`
- **Source**: `specs/posix/memory_error_info.table`
- **Description**: Data associated with errors of a physical memory array.
- **Columns**:
  - `handle` (`TEXT`): Handle, or instance number, associated with the structure
  - `error_type` (`TEXT`): type of error associated with current error status for array or device
  - `error_granularity` (`TEXT`): Granularity to which the error can be resolved
  - `error_operation` (`TEXT`): Memory access operation that caused the error
  - `vendor_syndrome` (`TEXT`): Vendor specific ECC syndrome or CRC data associated with the erroneous access
  - `memory_array_error_address` (`TEXT`): 32 bit physical address of the error based on the addressing of the bus to which the memory array is connected
  - `device_error_address` (`TEXT`): 32 bit physical address of the error relative to the start of the failing memory address, in bytes
  - `error_resolution` (`TEXT`): Range, in bytes, within which this error can be determined, when an error address is given

#### `cpu_info`
- **Source**: `specs/cpu_info.table`
- **Description**: Retrieve cpu hardware info of the machine.
- **Columns**:
  - `device_id` (`TEXT`): The DeviceID of the CPU.
  - `model` (`TEXT`): The model of the CPU.
  - `manufacturer` (`TEXT`): The manufacturer of the CPU.
  - `processor_type` (`TEXT`): The processor type, such as Central, Math, or Video.
  - `cpu_status` (`INTEGER`): The current operating status of the CPU.
  - `number_of_cores` (`TEXT`): The number of cores of the CPU.
  - `logical_processors` (`INTEGER`): The number of logical processors of the CPU.
  - `address_width` (`TEXT`): The width of the CPU address bus.
  - `current_clock_speed` (`INTEGER`): The current frequency of the CPU.
  - `max_clock_speed` (`INTEGER`): The maximum possible frequency of the CPU.
  - `socket_designation` (`TEXT`): The assigned socket on the board for the given CPU.

#### `cpuid`
- **Source**: `specs/cpuid.table` (x86_64)
- **Description**: Useful CPU features from the cpuid ASM call.
- **Columns**:
  - `feature` (`TEXT`): Present feature flags
  - `value` (`TEXT`): Bit value or string
  - `output_register` (`TEXT`): Register used to for feature value
  - `output_bit` (`INTEGER`): Bit in register value for feature value
  - `input_eax` (`TEXT`): Value of EAX used

#### `cpu_time`
- **Source**: `specs/posix/cpu_time.table`
- **Description**: Displays information from /proc/stat file about the time the cpu cores spent in different parts of the system.
- **Columns**:
  - `core` (`INTEGER`): Name of the cpu (core)
  - `user` (`BIGINT`): Time spent in user mode
  - `nice` (`BIGINT`): Time spent in user mode with low priority (nice)
  - `system` (`BIGINT`): Time spent in system mode
  - `idle` (`BIGINT`): Time spent in the idle task
  - `iowait` (`BIGINT`): Time spent waiting for I/O to complete
  - `irq` (`BIGINT`): Time spent servicing interrupts
  - `softirq` (`BIGINT`): Time spent servicing softirqs
  - `steal` (`BIGINT`): Time spent in other operating systems when running in a virtualized environment
  - `guest` (`BIGINT`): Time spent running a virtual CPU for a guest OS under the control of the Linux kernel
  - `guest_nice` (`BIGINT`): Time spent running a niced guest

#### `load_average`
- **Source**: `specs/posix/load_average.table`
- **Description**: Displays information about the system wide load averages.
- **Columns**:
  - `period` (`TEXT`): Period over which the average is calculated.
  - `average` (`TEXT`): Load average over the specified period.

---

### Category 3: Processes, Services, Namespaces & Resource Limits (9 Tables)

#### `processes`
- **Source**: `specs/processes.table`
- **Attributes**: `cacheable=True`
- **Description**: All running processes on the host system.
- **Columns**:
  - `pid` (`BIGINT`, `INDEX`, `OPTIMIZED`): Process (or thread) ID
  - `name` (`TEXT`): The process path or shorthand argv[0]
  - `path` (`TEXT`): Path to executed binary
  - `cmdline` (`TEXT`): Complete argv
  - `state` (`TEXT`): Process state
  - `cwd` (`TEXT`): Process current working directory
  - `root` (`TEXT`): Process virtual root directory
  - `uid` (`BIGINT`): Unsigned user ID
  - `gid` (`BIGINT`): Unsigned group ID
  - `euid` (`BIGINT`): Unsigned effective user ID
  - `egid` (`BIGINT`): Unsigned effective group ID
  - `suid` (`BIGINT`): Unsigned saved user ID
  - `sgid` (`BIGINT`): Unsigned saved group ID
  - `on_disk` (`INTEGER`): The process path exists yes=1, no=0, unknown=-1
  - `wired_size` (`BIGINT`): Bytes of unpageable memory used by process
  - `resident_size` (`BIGINT`): Bytes of private memory used by process
  - `total_size` (`BIGINT`): Total virtual memory size (Linux, Windows) or 'footprint' (macOS)
  - `user_time` (`BIGINT`): CPU time in milliseconds spent in user space
  - `system_time` (`BIGINT`): CPU time in milliseconds spent in kernel space
  - `disk_bytes_read` (`BIGINT`): Bytes read from disk
  - `disk_bytes_written` (`BIGINT`): Bytes written to disk
  - `start_time` (`BIGINT`): Process start time in seconds since Epoch, in case of error -1
  - `parent` (`BIGINT`): Process parent's PID
  - `pgroup` (`BIGINT`): Process group
  - `threads` (`INTEGER`): Number of threads used by process
  - `nice` (`INTEGER`): Process nice level (-20 to 20, default 0)
  - `cgroup_path` (`TEXT`, `LINUX`): The full hierarchical path of the process's control group

#### `process_envs`
- **Source**: `specs/posix/process_envs.table`
- **Description**: A key/value table of environment variables for each process.
- **Columns**:
  - `pid` (`INTEGER`, `INDEX`, `OPTIMIZED`): Process (or thread) ID
  - `key` (`TEXT`): Environment variable name
  - `value` (`TEXT`): Environment variable value

#### `process_memory_map`
- **Source**: `specs/process_memory_map.table`
- **Description**: Process memory mapped files and pseudo device/regions.
- **Columns**:
  - `pid` (`INTEGER`, `INDEX`, `OPTIMIZED`): Process (or thread) ID
  - `start` (`TEXT`): Virtual start address (hex)
  - `end` (`TEXT`): Virtual end address (hex)
  - `permissions` (`TEXT`): r=read, w=write, x=execute, p=private (cow)
  - `offset` (`BIGINT`): Offset into mapped path
  - `device` (`TEXT`): MA:MI Major/minor device ID
  - `inode` (`INTEGER`): Mapped path inode, 0 means uninitialized (BSS)
  - `path` (`TEXT`): Path to mapped file or mapped type
  - `pseudo` (`INTEGER`): 1 If path is a pseudo path, else 0

#### `process_namespaces`
- **Source**: `specs/linux/process_namespaces.table`
- **Description**: Linux namespaces for processes running on the host system.
- **Columns**:
  - `pid` (`INTEGER`, `INDEX`, `OPTIMIZED`): Process (or thread) ID
  - `cgroup_namespace` (`TEXT`): cgroup namespace inode
  - `ipc_namespace` (`TEXT`): ipc namespace inode
  - `mnt_namespace` (`TEXT`): mnt namespace inode
  - `net_namespace` (`TEXT`): net namespace inode
  - `pid_namespace` (`TEXT`): pid namespace inode
  - `user_namespace` (`TEXT`): user namespace inode
  - `uts_namespace` (`TEXT`): uts namespace inode

#### `process_open_files`
- **Source**: `specs/posix/process_open_files.table`
- **Description**: File descriptors for each process.
- **Columns**:
  - `pid` (`BIGINT`, `INDEX`): Process (or thread) ID
  - `fd` (`BIGINT`): Process-specific file descriptor number
  - `path` (`TEXT`): Filesystem path of descriptor

#### `process_open_pipes`
- **Source**: `specs/linux/process_open_pipes.table`
- **Description**: Pipes and partner processes for each process.
- **Columns**:
  - `pid` (`BIGINT`): Process ID
  - `fd` (`BIGINT`): File descriptor
  - `mode` (`TEXT`): Pipe open mode (r/w)
  - `inode` (`BIGINT`): Pipe inode number
  - `type` (`TEXT`): Pipe Type: named vs unnamed/anonymous
  - `partner_pid` (`BIGINT`): Process ID of partner process sharing a particular pipe
  - `partner_fd` (`BIGINT`): File descriptor of shared pipe at partner's end
  - `partner_mode` (`TEXT`): Mode of shared pipe at partner's end

#### `process_open_sockets`
- **Source**: `specs/process_open_sockets.table`
- **Description**: Processes which have open network sockets on the system.
- **Columns**:
  - `pid` (`INTEGER`, `ADDITIONAL`): Process (or thread) ID
  - `fd` (`BIGINT`): Socket file descriptor number
  - `socket` (`BIGINT`): Socket handle or inode number
  - `family` (`INTEGER`): Network protocol (IPv4, IPv6)
  - `protocol` (`INTEGER`): Transport protocol (TCP/UDP)
  - `local_address` (`TEXT`): Socket local address
  - `remote_address` (`TEXT`): Socket remote address
  - `local_port` (`INTEGER`): Socket local port
  - `remote_port` (`INTEGER`): Socket remote port
  - `path` (`TEXT`): For UNIX sockets (family=AF_UNIX), the domain path
  - `state` (`TEXT`): TCP socket state
  - `net_namespace` (`TEXT`, `LINUX`): The inode number of the network namespace

#### `systemd_units`
- **Source**: `specs/linux/systemd_units.table`
- **Description**: Track systemd units.
- **Columns**:
  - `id` (`TEXT`): Unique unit identifier
  - `description` (`TEXT`): Unit description
  - `load_state` (`TEXT`): Reflects whether the unit definition was properly loaded
  - `active_state` (`TEXT`): The high-level unit activation state, i.e. generalization of SUB
  - `sub_state` (`TEXT`): The low-level unit activation state, values depend on unit type
  - `unit_file_state` (`TEXT`): Whether the unit file is enabled, e.g. `enabled`, `masked`, `disabled`, etc
  - `following` (`TEXT`): The name of another unit that this unit follows in state
  - `object_path` (`TEXT`): The object path for this unit
  - `job_id` (`BIGINT`): Next queued job id
  - `job_type` (`TEXT`): Job type
  - `job_path` (`TEXT`): The object path for the job
  - `fragment_path` (`TEXT`): The unit file path this unit was read from, if there is any
  - `user` (`TEXT`): The configured user, if any
  - `source_path` (`TEXT`): Path to the (possibly generated) unit configuration file

#### `ulimit_info`
- **Source**: `specs/posix/ulimit_info.table`
- **Description**: System resource usage limits.
- **Columns**:
  - `type` (`TEXT`): System resource to be limited
  - `soft_limit` (`TEXT`): Current limit value
  - `hard_limit` (`TEXT`): Maximum limit value

---

### Category 4: Storage, Filesystems, Block Devices, RAID & Forensics (14 Tables)

#### `mounts`
- **Source**: `specs/posix/mounts.table`
- **Description**: System mounted devices and filesystems (not process specific).
- **Columns**:
  - `device` (`TEXT`): Mounted device
  - `device_alias` (`TEXT`): Mounted device alias
  - `path` (`TEXT`): Mounted device path
  - `type` (`TEXT`): Mounted device type
  - `blocks_size` (`BIGINT`): Block size in bytes
  - `blocks` (`BIGINT`): Mounted device used blocks
  - `blocks_free` (`BIGINT`): Mounted device blocks available to root users, a superset of blocks_available
  - `blocks_available` (`BIGINT`): Mounted device blocks available to non-root users
  - `inodes` (`BIGINT`): Mounted device used inodes
  - `inodes_free` (`BIGINT`): Mounted device free inodes
  - `flags` (`TEXT`): Mounted device flags

#### `block_devices`
- **Source**: `specs/posix/block_devices.table`
- **Description**: Block (buffered access) device file nodes: disks, ramdisks, and DMG containers.
- **Columns**:
  - `name` (`TEXT`, `INDEX`): Block device name
  - `parent` (`TEXT`): Block device parent name
  - `vendor` (`TEXT`): Block device vendor string
  - `model` (`TEXT`): Block device model string identifier
  - `serial` (`TEXT`): Disk serial number
  - `size` (`BIGINT`): Block device size in blocks
  - `block_size` (`INTEGER`): Block size in bytes
  - `uuid` (`TEXT`): Block device Universally Unique Identifier
  - `type` (`TEXT`): Block device type string
  - `label` (`TEXT`): Block device label string

#### `disk_encryption`
- **Source**: `specs/posix/disk_encryption.table`
- **Description**: Disk encryption status and information.
- **Columns**:
  - `name` (`TEXT`, `INDEX`): Disk name
  - `uuid` (`TEXT`): Disk Universally Unique Identifier
  - `encrypted` (`INTEGER`): 1 If encrypted: true (disk is encrypted), else 0
  - `type` (`TEXT`): Description of cipher type and mode if available
  - `encryption_status` (`TEXT`): Disk encryption status with one of following values: encrypted | not encrypted | undefined

#### `md_devices`
- **Source**: `specs/linux/md_devices.table`
- **Description**: Software RAID array settings.
- **Columns**:
  - `device_name` (`TEXT`): md device name
  - `status` (`TEXT`): Current state of the array
  - `raid_level` (`INTEGER`): Current raid level of the array
  - `size` (`BIGINT`): size of the array in blocks
  - `chunk_size` (`BIGINT`): chunk size in bytes
  - `raid_disks` (`INTEGER`): Number of configured RAID disks in array
  - `nr_raid_disks` (`INTEGER`): Number of partitions or disk devices to comprise the array
  - `working_disks` (`INTEGER`): Number of working disks in array
  - `active_disks` (`INTEGER`): Number of active disks in array
  - `failed_disks` (`INTEGER`): Number of failed disks in array
  - `spare_disks` (`INTEGER`): Number of idle disks in array
  - `superblock_state` (`TEXT`): State of the superblock
  - `superblock_version` (`TEXT`): Version of the superblock
  - `superblock_update_time` (`BIGINT`): Unix timestamp of last update
  - `bitmap_on_mem` (`TEXT`): Pages allocated in in-memory bitmap, if enabled
  - `bitmap_chunk_size` (`TEXT`): Bitmap chunk size
  - `bitmap_external_file` (`TEXT`): External referenced bitmap file
  - `recovery_progress` (`TEXT`): Progress of the recovery activity
  - `recovery_finish` (`TEXT`): Estimated duration of recovery activity
  - `recovery_speed` (`TEXT`): Speed of recovery activity
  - `resync_progress` (`TEXT`): Progress of the resync activity
  - `resync_finish` (`TEXT`): Estimated duration of resync activity
  - `resync_speed` (`TEXT`): Speed of resync activity
  - `reshape_progress` (`TEXT`): Progress of the reshape activity
  - `reshape_finish` (`TEXT`): Estimated duration of reshape activity
  - `reshape_speed` (`TEXT`): Speed of reshape activity
  - `check_array_progress` (`TEXT`): Progress of the check array activity
  - `check_array_finish` (`TEXT`): Estimated duration of the check array activity
  - `check_array_speed` (`TEXT`): Speed of the check array activity
  - `unused_devices` (`TEXT`): Unused devices
  - `other` (`TEXT`): Other information associated with array from /proc/mdstat

#### `md_drives`
- **Source**: `specs/linux/md_drives.table`
- **Description**: Drive devices used for Software RAID.
- **Columns**:
  - `md_device_name` (`TEXT`): md device name
  - `drive_name` (`TEXT`): Drive device name
  - `slot` (`INTEGER`): Slot position of disk
  - `state` (`TEXT`): State of the drive

#### `md_personalities`
- **Source**: `specs/linux/md_personalities.table`
- **Description**: Software RAID setting supported by the kernel.
- **Columns**:
  - `name` (`TEXT`): Name of personality supported by kernel

#### `file`
- **Source**: `specs/utility/file.table`
- **Attributes**: `utility=True`
- **Required `WHERE` Constraints**: Must provide `path` OR `directory` in `WHERE`.
- **Description**: Interactive filesystem attributes and metadata.
- **Columns**:
  - `path` (`TEXT`, `REQUIRED`, `INDEX`, `OPTIMIZED`): Absolute file path
  - `directory` (`TEXT`, `REQUIRED`, `OPTIMIZED`): Directory of file(s)
  - `filename` (`TEXT`): Name portion of file path
  - `inode` (`BIGINT`): Filesystem inode number
  - `uid` (`BIGINT`): Owning user ID
  - `gid` (`BIGINT`): Owning group ID
  - `mode` (`TEXT`): Permission bits
  - `device` (`BIGINT`): Device ID (optional)
  - `size` (`BIGINT`): Size of file in bytes
  - `block_size` (`INTEGER`): Block size of filesystem
  - `atime` (`BIGINT`): Last access time
  - `mtime` (`BIGINT`): Last modification time
  - `ctime` (`BIGINT`): Last status change time
  - `btime` (`BIGINT`): (B)irth or (cr)eate time
  - `hard_links` (`INTEGER`): Number of hard links
  - `symlink` (`INTEGER`): 1 if the path is a symlink, otherwise 0
  - `type` (`TEXT`): File status
  - `symlink_target_path` (`TEXT`): Full path of the symlink target if any
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace
  - `mount_namespace_id` (`TEXT`, `HIDDEN`, `LINUX`): Mount namespace id

#### `hash`
- **Source**: `specs/hash.table`
- **Required `WHERE` Constraints**: Must provide `path` OR `directory` in `WHERE`.
- **Description**: Filesystem hash data.
- **Columns**:
  - `path` (`TEXT`, `REQUIRED`, `INDEX`, `OPTIMIZED`): Must provide a path or directory
  - `directory` (`TEXT`, `REQUIRED`, `OPTIMIZED`): Must provide a path or directory
  - `md5` (`TEXT`): MD5 hash of provided filesystem data
  - `sha1` (`TEXT`): SHA1 hash of provided filesystem data
  - `sha256` (`TEXT`): SHA256 hash of provided filesystem data
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace
  - `mount_namespace_id` (`TEXT`, `HIDDEN`, `LINUX`): Mount namespace id

#### `magic`
- **Source**: `specs/posix/magic.table`
- **Required `WHERE` Constraints**: Must provide `path` in `WHERE`.
- **Description**: Magic number recognition library table.
- **Columns**:
  - `path` (`TEXT`, `REQUIRED`, `INDEX`): Absolute path to target file
  - `magic_db_files` (`TEXT`, `ADDITIONAL`): Colon(:) separated list of files where the magic db file can be found. By default one of the following is used: /usr/share/file/magic/magic, /usr/share/misc/magic or /usr/share/misc/magic.mgc
  - `data` (`TEXT`): Magic number data from libmagic
  - `mime_type` (`TEXT`): MIME type data from libmagic
  - `mime_encoding` (`TEXT`): MIME encoding data from libmagic

#### `extended_attributes`
- **Source**: `specs/posix/extended_attributes.table`
- **Required `WHERE` Constraints**: Must provide `path` OR `directory` in `WHERE`.
- **Description**: Returns the extended attributes for files (similar to Windows ADS).
- **Columns**:
  - `path` (`TEXT`, `REQUIRED`, `OPTIMIZED`): Absolute file path
  - `directory` (`TEXT`, `REQUIRED`, `OPTIMIZED`): Directory of file(s)
  - `key` (`TEXT`): Name of the value generated from the extended attribute
  - `value` (`TEXT`): The parsed information from the attribute
  - `base64` (`INTEGER`): 1 if the value is base64 encoded else 0

#### `carves`
- **Source**: `specs/carves.table`
- **Description**: List the set of completed and in-progress carves. If carve=1 then the query is treated as a new carve request.
- **Columns**:
  - `time` (`BIGINT`): Time at which the carve was kicked off
  - `sha256` (`TEXT`): A SHA256 sum of the carved archive
  - `size` (`BIGINT`): Size in bytes of the carved archive
  - `path` (`TEXT`, `ADDITIONAL`): The path of the requested carve
  - `status` (`TEXT`): Status of the carve, can be STARTING, PENDING, SUCCESS, or FAILED
  - `carve_guid` (`TEXT`, `INDEX`): Identifying value of the carve session
  - `request_id` (`TEXT`): Identifying value of the carve request (e.g., scheduled query name, distributed request, etc)
  - `carve` (`INTEGER`, `ADDITIONAL`): Set this value to '1' to start a file carve

#### `device_partitions`
- **Source**: `specs/sleuthkit/device_partitions.table`
- **Required `WHERE` Constraints**: Must provide `device` in `WHERE`.
- **Description**: Use TSK to enumerate details about partitions on a disk device.
- **Columns**:
  - `device` (`TEXT`, `REQUIRED`): Absolute file path to device node
  - `partition` (`INTEGER`): A partition number or description
  - `label` (`TEXT`): The partition name as stored in the partition table
  - `type` (`TEXT`): Filesystem type if recognized, otherwise, 'meta', 'normal', or 'unallocated'
  - `offset` (`BIGINT`): Byte offset from the start of the volume
  - `blocks_size` (`BIGINT`): Byte size of each block
  - `blocks` (`BIGINT`): Number of blocks
  - `inodes` (`BIGINT`): Number of meta nodes
  - `flags` (`INTEGER`): Value that describes the partition (TSK_VS_PART_FLAG_ENUM)

#### `device_file`
- **Source**: `specs/sleuthkit/device_file.table`
- **Required `WHERE` Constraints**: Must provide `device` AND `partition` in `WHERE`.
- **Description**: Similar to the file table, but use TSK and allow block address access.
- **Columns**:
  - `device` (`TEXT`, `REQUIRED`, `INDEX`): Absolute file path to device node
  - `partition` (`TEXT`, `REQUIRED`, `INDEX`): A partition number
  - `path` (`TEXT`, `ADDITIONAL`): A logical path within the device node
  - `filename` (`TEXT`): Name portion of file path
  - `inode` (`BIGINT`, `INDEX`): Filesystem inode number
  - `uid` (`BIGINT`): Owning user ID
  - `gid` (`BIGINT`): Owning group ID
  - `mode` (`TEXT`): Permission bits
  - `size` (`BIGINT`): Size of file in bytes
  - `block_size` (`INTEGER`): Block size of filesystem
  - `atime` (`BIGINT`): Last access time
  - `mtime` (`BIGINT`): Last modification time
  - `ctime` (`BIGINT`): Creation time
  - `hard_links` (`INTEGER`): Number of hard links
  - `type` (`TEXT`): File status

#### `device_hash`
- **Source**: `specs/sleuthkit/device_hash.table`
- **Required `WHERE` Constraints**: Must provide `device`, `partition`, AND `inode` in `WHERE`.
- **Description**: Similar to the hash table, but use TSK and allow block address access.
- **Columns**:
  - `device` (`TEXT`, `REQUIRED`): Absolute file path to device node
  - `partition` (`TEXT`, `REQUIRED`): A partition number
  - `inode` (`BIGINT`, `REQUIRED`): Filesystem inode number
  - `md5` (`TEXT`): MD5 hash of provided inode data
  - `sha1` (`TEXT`): SHA1 hash of provided inode data
  - `sha256` (`TEXT`): SHA256 hash of provided inode data

---

### Category 5: Networking, Routing, DNS, Firewall & TLS/HTTP (13 Tables)

#### `interface_addresses`
- **Source**: `specs/interface_addresses.table`
- **Attributes**: `cacheable=True`
- **Description**: Network interfaces and relevant metadata.
- **Columns**:
  - `interface` (`TEXT`): Interface name
  - `address` (`TEXT`): Specific address for interface
  - `mask` (`TEXT`): Interface netmask
  - `broadcast` (`TEXT`): Broadcast address for the interface
  - `point_to_point` (`TEXT`): PtP address for the interface
  - `type` (`TEXT`): Type of address. One of dhcp, manual, auto, other, unknown

#### `interface_details`
- **Source**: `specs/interface_details.table`
- **Attributes**: `cacheable=True`
- **Description**: Detailed information and stats of network interfaces.
- **Columns**:
  - `interface` (`TEXT`): Interface name
  - `mac` (`TEXT`): MAC of interface (optional)
  - `type` (`INTEGER`): Interface type (includes virtual)
  - `mtu` (`INTEGER`): Network MTU
  - `metric` (`INTEGER`): Metric based on the speed of the interface
  - `flags` (`INTEGER`): Flags (netdevice) for the device
  - `ipackets` (`BIGINT`): Input packets
  - `opackets` (`BIGINT`): Output packets
  - `ibytes` (`BIGINT`): Input bytes
  - `obytes` (`BIGINT`): Output bytes
  - `ierrors` (`BIGINT`): Input errors
  - `oerrors` (`BIGINT`): Output errors
  - `idrops` (`BIGINT`): Input drops
  - `odrops` (`BIGINT`): Output drops
  - `collisions` (`BIGINT`): Packet Collisions detected
  - `last_change` (`BIGINT`): Time of last device modification (optional)
  - `link_speed` (`BIGINT`, `LINUX`): Interface speed in Mb/s
  - `pci_slot` (`TEXT`, `LINUX`): PCI slot number

#### `interface_ipv6`
- **Source**: `specs/posix/interface_ipv6.table`
- **Description**: IPv6 configuration and stats of network interfaces.
- **Columns**:
  - `interface` (`TEXT`): Interface name
  - `hop_limit` (`INTEGER`): Current Hop Limit
  - `forwarding_enabled` (`INTEGER`): Enable IP forwarding
  - `redirect_accept` (`INTEGER`): Accept ICMP redirect messages
  - `rtadv_accept` (`INTEGER`): Accept ICMP Router Advertisement

#### `listening_ports`
- **Source**: `specs/listening_ports.table`
- **Attributes**: `cacheable=True`
- **Description**: Processes with listening (bound) network sockets/ports.
- **Columns**:
  - `pid` (`INTEGER`): Process (or thread) ID
  - `port` (`INTEGER`): Transport layer port
  - `protocol` (`INTEGER`): Transport protocol (TCP/UDP)
  - `family` (`INTEGER`): Network protocol (IPv4, IPv6)
  - `address` (`TEXT`): Specific address for bind
  - `fd` (`BIGINT`): Socket file descriptor number
  - `socket` (`BIGINT`): Socket handle or inode number
  - `path` (`TEXT`): Path for UNIX domain sockets
  - `net_namespace` (`TEXT`, `LINUX`): The inode number of the network namespace

#### `routes`
- **Source**: `specs/routes.table`
- **Attributes**: `cacheable=True`
- **Description**: The active route table for the host system.
- **Columns**:
  - `destination` (`TEXT`): Destination IP address
  - `netmask` (`INTEGER`): Netmask length
  - `gateway` (`TEXT`): Route gateway
  - `source` (`TEXT`): Route source
  - `flags` (`INTEGER`): Flags to describe route
  - `interface` (`TEXT`): Route local interface
  - `mtu` (`INTEGER`): Maximum Transmission Unit for the route
  - `metric` (`INTEGER`): Cost of route. Lowest is preferred
  - `type` (`TEXT`, `ADDITIONAL`): Type of route
  - `hopcount` (`INTEGER`, `LINUX`): Max hops expected

#### `arp_cache`
- **Source**: `specs/arp_cache.table`
- **Description**: Address resolution cache, both static and dynamic (from ARP, NDP).
- **Columns**:
  - `address` (`TEXT`): IPv4 address target
  - `mac` (`TEXT`): MAC address of broadcasted address
  - `interface` (`TEXT`): Interface of the network for the MAC
  - `permanent` (`TEXT`): 1 for true, 0 for false

#### `dns_resolvers`
- **Source**: `specs/posix/dns_resolvers.table`
- **Description**: Resolvers used by this host.
- **Columns**:
  - `id` (`INTEGER`): Address type index or order
  - `type` (`TEXT`): Address type: sortlist, nameserver, search
  - `address` (`TEXT`): Resolver IP/IPv6 address
  - `netmask` (`TEXT`): Address (sortlist) netmask length
  - `options` (`BIGINT`): Resolver options
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `etc_hosts` (alias: `hosts`)
- **Source**: `specs/etc_hosts.table`
- **Attributes**: `cacheable=True`
- **Description**: Line-parsed /etc/hosts.
- **Columns**:
  - `address` (`TEXT`): IP address mapping
  - `hostnames` (`TEXT`): Raw hosts mapping
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `etc_protocols`
- **Source**: `specs/etc_protocols.table`
- **Attributes**: `cacheable=True`
- **Description**: Line-parsed /etc/protocols.
- **Columns**:
  - `name` (`TEXT`): Protocol name
  - `number` (`INTEGER`): Protocol number
  - `alias` (`TEXT`): Protocol alias
  - `comment` (`TEXT`): Comment with protocol description

#### `etc_services`
- **Source**: `specs/etc_services.table`
- **Attributes**: `cacheable=True`
- **Description**: Line-parsed /etc/services.
- **Columns**:
  - `name` (`TEXT`): Service name
  - `port` (`INTEGER`): Service port number
  - `protocol` (`TEXT`): Transport protocol (TCP/UDP)
  - `aliases` (`TEXT`): Optional space separated list of other names for a service
  - `comment` (`TEXT`): Optional comment for a service.

#### `iptables`
- **Source**: `specs/linux/iptables.table`
- **Description**: Linux IP packet filtering and NAT tool.
- **Columns**:
  - `filter_name` (`TEXT`): Packet matching filter table name.
  - `chain` (`TEXT`): Size of module content.
  - `policy` (`TEXT`): Policy that applies for this rule.
  - `target` (`TEXT`): Target that applies for this rule.
  - `protocol` (`INTEGER`): Protocol number identification.
  - `src_port` (`TEXT`): Protocol source port(s).
  - `dst_port` (`TEXT`): Protocol destination port(s).
  - `src_ip` (`TEXT`): Source IP address.
  - `src_mask` (`TEXT`): Source IP address mask.
  - `iniface` (`TEXT`): Input interface for the rule.
  - `iniface_mask` (`TEXT`): Input interface mask for the rule.
  - `dst_ip` (`TEXT`): Destination IP address.
  - `dst_mask` (`TEXT`): Destination IP address mask.
  - `outiface` (`TEXT`): Output interface for the rule.
  - `outiface_mask` (`TEXT`): Output interface mask for the rule.
  - `match` (`TEXT`): Matching rule that applies.
  - `packets` (`INTEGER`): Number of matching packets for this rule.
  - `bytes` (`INTEGER`): Number of matching bytes for this rule.

#### `curl`
- **Source**: `specs/curl.table`
- **Required `WHERE` Constraints**: Must provide `url` in `WHERE`.
- **Description**: Perform an http request and return stats about it.
- **Columns**:
  - `url` (`TEXT`, `REQUIRED`, `INDEX`, `OPTIMIZED`): The url for the request
  - `method` (`TEXT`): The HTTP method for the request
  - `user_agent` (`TEXT`, `ADDITIONAL`): The user-agent string to use for the request
  - `response_code` (`INTEGER`): The HTTP status code for the response
  - `round_trip_time` (`BIGINT`): Time taken to complete the request
  - `bytes` (`BIGINT`): Number of bytes in the response
  - `result` (`TEXT`): The HTTP response body

#### `curl_certificate`
- **Source**: `specs/curl_certificate.table`
- **Required `WHERE` Constraints**: Must provide `hostname` in `WHERE`.
- **Description**: Inspect TLS certificates by connecting to input hostnames.
- **Columns**:
  - `hostname` (`TEXT`, `REQUIRED`, `OPTIMIZED`): Hostname to CURL (domain[:port], e.g. osquery.io)
  - `common_name` (`TEXT`): Common name of company issued to
  - `organization` (`TEXT`): Organization issued to
  - `organization_unit` (`TEXT`): Organization unit issued to
  - `serial_number` (`TEXT`): Certificate serial number
  - `issuer_common_name` (`TEXT`): Issuer common name
  - `issuer_organization` (`TEXT`): Issuer organization
  - `issuer_organization_unit` (`TEXT`): Issuer organization unit
  - `valid_from` (`TEXT`): Period of validity start date
  - `valid_to` (`TEXT`): Period of validity end date
  - `sha256_fingerprint` (`TEXT`): SHA-256 fingerprint
  - `sha1_fingerprint` (`TEXT`): SHA1 fingerprint
  - `version` (`INTEGER`): Version Number
  - `signature_algorithm` (`TEXT`): Signature Algorithm
  - `signature` (`TEXT`): Signature
  - `subject_key_identifier` (`TEXT`): Subject Key Identifier
  - `authority_key_identifier` (`TEXT`): Authority Key Identifier
  - `key_usage` (`TEXT`): Usage of key in certificate
  - `extended_key_usage` (`TEXT`): Extended usage of key in certificate
  - `policies` (`TEXT`): Certificate Policies
  - `subject_alternative_names` (`TEXT`): Subject Alternative Name
  - `issuer_alternative_names` (`TEXT`): Issuer Alternative Name
  - `info_access` (`TEXT`): Authority Information Access
  - `subject_info_access` (`TEXT`): Subject Information Access
  - `policy_mappings` (`TEXT`): Policy Mappings
  - `has_expired` (`INTEGER`): 1 if the certificate has expired, 0 otherwise
  - `basic_constraint` (`TEXT`): Basic Constraints
  - `name_constraints` (`TEXT`): Name Constraints
  - `policy_constraints` (`TEXT`): Policy Constraints
  - `dump_certificate` (`INTEGER`, `ADDITIONAL`, `HIDDEN`): Set this value to '1' to dump certificate
  - `timeout` (`INTEGER`, `ADDITIONAL`, `HIDDEN`): Set this value to the timeout in seconds to complete the TLS handshake (default 4s, use 0 for no timeout)
  - `pem` (`TEXT`): Certificate PEM format
  - `tls_version` (`TEXT`): TLS protocol version negotiated for the connection; empty if the handshake did not complete
  - `cipher_suite` (`TEXT`): IANA name of the cipher suite negotiated for the connection; empty if the handshake did not complete
  - `cipher_bits` (`INTEGER`): Number of secret/key bits used by the negotiated cipher suite; NULL if the handshake did not complete

---

### Category 6: Users, Groups, Authentication, SSH & Privilege Escalation (13 Tables)

#### `users`
- **Source**: `specs/users.table`
- **Description**: Local user accounts.
- **Columns**:
  - `uid` (`BIGINT`, `INDEX`): User ID
  - `gid` (`BIGINT`): Group ID (unsigned)
  - `uid_signed` (`BIGINT`): User ID as int64 signed (Apple)
  - `gid_signed` (`BIGINT`): Default group ID as int64 signed (Apple)
  - `username` (`TEXT`, `ADDITIONAL`): Username
  - `description` (`TEXT`): Optional user description
  - `directory` (`TEXT`): User's home directory
  - `shell` (`TEXT`): User's configured default shell
  - `uuid` (`TEXT`, `INDEX`): User's UUID (Apple) or SID (Windows)
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace
  - `include_remote` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): 1 to include remote (LDAP/AD) accounts (default 0)

#### `groups`
- **Source**: `specs/groups.table`
- **Description**: Local system groups.
- **Columns**:
  - `gid` (`BIGINT`, `INDEX`): Unsigned int64 group ID
  - `gid_signed` (`BIGINT`): A signed int64 version of gid
  - `groupname` (`TEXT`): Canonical local group name
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `user_groups`
- **Source**: `specs/user_groups.table`
- **Description**: Local system user group relationships.
- **Columns**:
  - `uid` (`BIGINT`, `INDEX`, `OPTIMIZED`): User ID
  - `gid` (`BIGINT`, `INDEX`): Group ID

#### `logged_in_users`
- **Source**: `specs/logged_in_users.table`
- **Attributes**: `cacheable=True`
- **Description**: Users with an active shell on the system.
- **Columns**:
  - `type` (`TEXT`): Login type
  - `user` (`TEXT`): User login name
  - `tty` (`TEXT`): Device name
  - `host` (`TEXT`): Remote hostname
  - `time` (`BIGINT`): Time entry was made
  - `pid` (`INTEGER`): Process (or thread) ID

#### `last`
- **Source**: `specs/posix/last.table`
- **Attributes**: `cacheable=True`
- **Description**: System logins and logouts.
- **Columns**:
  - `username` (`TEXT`): Entry username
  - `tty` (`TEXT`): Entry terminal
  - `pid` (`INTEGER`): Process (or thread) ID
  - `type` (`INTEGER`): Entry type, according to ut_type types (utmp.h)
  - `type_name` (`TEXT`): Entry type name, according to ut_type types (utmp.h)
  - `time` (`INTEGER`): Entry timestamp
  - `host` (`TEXT`): Entry hostname

#### `shadow`
- **Source**: `specs/linux/shadow.table`
- **Description**: Local system users encrypted passwords and related information. Please note, that you usually need superuser rights to access `/etc/shadow`.
- **Columns**:
  - `password_status` (`TEXT`): Password status
  - `hash_alg` (`TEXT`): Password hashing algorithm
  - `last_change` (`BIGINT`): Date of last password change (starting from UNIX epoch date)
  - `min` (`BIGINT`): Minimal number of days between password changes
  - `max` (`BIGINT`): Maximum number of days between password changes
  - `warning` (`BIGINT`): Number of days before password expires to warn user about it
  - `inactive` (`BIGINT`): Number of days after password expires until account is blocked
  - `expire` (`BIGINT`): Number of days since UNIX epoch date until account is disabled
  - `flag` (`BIGINT`): Reserved
  - `username` (`TEXT`, `INDEX`, `OPTIMIZED`): Username

#### `sudoers`
- **Source**: `specs/posix/sudoers.table`
- **Description**: Rules for running commands as other users via sudo.
- **Columns**:
  - `source` (`TEXT`): Source file containing the given rule
  - `header` (`TEXT`): Symbol for given rule
  - `rule_details` (`TEXT`): Rule definition

#### `suid_bin`
- **Source**: `specs/posix/suid_bin.table`
- **Attributes**: `cacheable=True`
- **Description**: suid binaries in common locations.
- **Columns**:
  - `path` (`TEXT`): Binary path
  - `username` (`TEXT`): Binary owner username
  - `groupname` (`TEXT`): Binary owner group
  - `permissions` (`TEXT`): Binary permissions
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `authorized_keys`
- **Source**: `specs/posix/authorized_keys.table`
- **Attributes**: `user_data=True` (Join with `users USING (uid)` or specify `WHERE uid = ...`)
- **Description**: A line-delimited authorized_keys table.
- **Columns**:
  - `uid` (`BIGINT`, `ADDITIONAL`): The local owner of authorized_keys file
  - `algorithm` (`TEXT`): Key type
  - `key` (`TEXT`): Key encoded as base64
  - `options` (`TEXT`): Optional list of login options
  - `comment` (`TEXT`): Optional comment
  - `key_file` (`TEXT`): Path to the authorized_keys file
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `known_hosts`
- **Source**: `specs/posix/known_hosts.table`
- **Attributes**: `user_data=True` (Join with `users USING (uid)` or specify `WHERE uid = ...`)
- **Description**: A line-delimited known_hosts table.
- **Columns**:
  - `uid` (`BIGINT`, `INDEX`, `OPTIMIZED`): The local user that owns the known_hosts file
  - `key` (`TEXT`): parsed authorized keys line
  - `key_file` (`TEXT`): Path to known_hosts file

#### `user_ssh_keys`
- **Source**: `specs/user_ssh_keys.table`
- **Attributes**: `user_data=True` (Join with `users USING (uid)` or specify `WHERE uid = ...`)
- **Description**: Returns the private keys in the users ~/.ssh directory and whether or not they are encrypted.
- **Columns**:
  - `uid` (`BIGINT`, `ADDITIONAL`, `OPTIMIZED`): The local user that owns the key file
  - `path` (`TEXT`, `INDEX`): Path to key file
  - `encrypted` (`INTEGER`): 1 if key is encrypted, 0 otherwise
  - `key_type` (`TEXT`): The type of the private key. One of [rsa, dsa, dh, ec, hmac, cmac], or the empty string.
  - `key_group_name` (`TEXT`): The group of the private key. Supported for a subset of key_types implemented by OpenSSL
  - `key_length` (`INTEGER`): The cryptographic length of the cryptosystem to which the private key belongs, in bits. -1 if unavailable
  - `key_security_bits` (`INTEGER`): The number of security bits of the private key, bits of security as defined in NIST SP800-57. -1 if unavailable
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `ssh_configs`
- **Source**: `specs/ssh_configs.table`
- **Attributes**: `user_data=True` (Join with `users USING (uid)` or specify `WHERE uid = ...`)
- **Description**: A table of parsed ssh_configs.
- **Columns**:
  - `uid` (`BIGINT`, `ADDITIONAL`, `OPTIMIZED`): The local owner of the ssh_config file
  - `block` (`TEXT`): The host or match block
  - `option` (`TEXT`): The option and value
  - `ssh_config_file` (`TEXT`): Path to the ssh_config file

#### `shell_history`
- **Source**: `specs/posix/shell_history.table`
- **Attributes**: `user_data=True` (Join with `users USING (uid)` or specify `WHERE uid = ...`)
- **Description**: A line-delimited (command) table of per-user .*_history data.
- **Columns**:
  - `uid` (`BIGINT`, `ADDITIONAL`, `OPTIMIZED`): Shell history owner
  - `time` (`INTEGER`): Entry timestamp. It could be absent, default value is 0.
  - `command` (`TEXT`): Unparsed date/line/command history line
  - `history_file` (`TEXT`): Path to the .*_history for this user

---

### Category 7: Startup, Scheduled Tasks & Configuration Parsing (3 Tables)

#### `crontab`
- **Source**: `specs/posix/crontab.table`
- **Attributes**: `cacheable=True`
- **Description**: Line parsed values from system and user cron/tab.
- **Columns**:
  - `event` (`TEXT`): The job @event name (rare)
  - `minute` (`TEXT`): The exact minute for the job
  - `hour` (`TEXT`): The hour of the day for the job
  - `day_of_month` (`TEXT`): The day of the month for the job
  - `month` (`TEXT`): The month of the year for the job
  - `day_of_week` (`TEXT`): The day of the week for the job
  - `command` (`TEXT`): Raw command string
  - `path` (`TEXT`): File parsed
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `startup_items`
- **Source**: `specs/startup_items.table`
- **Attributes**: `cacheable=True`
- **Description**: Applications and binaries set as startup items.
- **Columns**:
  - `name` (`TEXT`): Name of startup item
  - `path` (`TEXT`): Path of startup item
  - `args` (`TEXT`): Arguments provided to startup executable
  - `type` (`TEXT`): Type of startup item
  - `source` (`TEXT`): Directory containing startup item
  - `status` (`TEXT`): Startup status. On Linux: enabled or disabled
  - `username` (`TEXT`): The user associated with the startup item

#### `augeas` (alias: `configurations`)
- **Source**: `specs/posix/augeas.table`
- **Description**: Configuration files parsed by augeas.
- **Columns**:
  - `node` (`TEXT`, `INDEX`): The node path of the configuration item
  - `value` (`TEXT`): The value of the configuration item
  - `label` (`TEXT`): The label of the configuration item
  - `path` (`TEXT`, `ADDITIONAL`): The path to the configuration file


---

### Category 8: Software Packages & Repositories (14 Tables)

#### `apt_sources`
- **Source**: `specs/linux/apt_sources.table`
- **Description**: Current list of APT repositories or software channels.
- **Columns**:
  - `name` (`TEXT`): Repository name
  - `source` (`TEXT`): Source file
  - `base_uri` (`TEXT`): Repository base URI
  - `release` (`TEXT`): Release name
  - `version` (`TEXT`): Repository source version
  - `maintainer` (`TEXT`): Repository maintainer
  - `components` (`TEXT`): Repository components
  - `architectures` (`TEXT`): Repository architectures
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `deb_packages`
- **Source**: `specs/linux/deb_packages.table`
- **Attributes**: `cacheable=True`
- **Description**: The installed DEB package database.
- **Columns**:
  - `name` (`TEXT`): Package name
  - `version` (`TEXT`): Package version
  - `source` (`TEXT`): Package source
  - `size` (`BIGINT`): Package size in bytes
  - `arch` (`TEXT`): Package architecture
  - `revision` (`TEXT`): Package revision
  - `status` (`TEXT`): Package status
  - `maintainer` (`TEXT`): Package maintainer
  - `section` (`TEXT`): Package section
  - `priority` (`TEXT`): Package priority
  - `admindir` (`TEXT`, `ADDITIONAL`, `OPTIMIZED`): libdpkg admindir. Defaults to /var/lib/dpkg
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace
  - `mount_namespace_id` (`TEXT`, `HIDDEN`, `LINUX`): Mount namespace id

#### `deb_package_files`
- **Source**: `specs/linux/deb_package_files.table`
- **Description**: Installed files from DEB packages that are currently installed on the system.
- **Columns**:
  - `package` (`TEXT`, `INDEX`, `OPTIMIZED`): DEB package name
  - `path` (`TEXT`, `INDEX`): File path within the package
  - `admindir` (`TEXT`, `ADDITIONAL`, `OPTIMIZED`): libdpkg admindir. Defaults to /var/lib/dpkg

#### `yum_sources`
- **Source**: `specs/linux/yum_sources.table`
- **Description**: Current list of Yum repositories or software channels.
- **Columns**:
  - `name` (`TEXT`): Repository name
  - `source` (`TEXT`): Source file
  - `baseurl` (`TEXT`): Repository base URL
  - `mirrorlist` (`TEXT`): Mirrorlist URL
  - `metalink` (`TEXT`): Metalink URL
  - `enabled` (`TEXT`): Whether the repository is used
  - `gpgcheck` (`TEXT`): Whether packages are GPG checked
  - `gpgkey` (`TEXT`): URL to GPG key
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `rpm_packages`
- **Source**: `specs/linux/rpm_packages.table`
- **Attributes**: `cacheable=True`
- **Description**: RPM packages that are currently installed on the host system.
- **Columns**:
  - `name` (`TEXT`, `INDEX`, `OPTIMIZED`): RPM package name
  - `version` (`TEXT`, `INDEX`): Package version
  - `release` (`TEXT`, `INDEX`): Package release
  - `source` (`TEXT`): Source RPM package name (optional)
  - `size` (`BIGINT`): Package size in bytes
  - `sha1` (`TEXT`): SHA1 hash of the package contents
  - `arch` (`TEXT`, `INDEX`): Architecture(s) supported
  - `epoch` (`INTEGER`, `INDEX`): Package epoch value
  - `install_time` (`INTEGER`): When the package was installed
  - `vendor` (`TEXT`): Package vendor
  - `package_group` (`TEXT`): Package group
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace
  - `mount_namespace_id` (`TEXT`, `HIDDEN`, `LINUX`): Mount namespace id

#### `rpm_package_files`
- **Source**: `specs/linux/rpm_package_files.table`
- **Description**: Installed files from RPM packages that are currently installed on the system.
- **Columns**:
  - `package` (`TEXT`, `INDEX`, `OPTIMIZED`): RPM package name
  - `path` (`TEXT`, `INDEX`): File path within the package
  - `username` (`TEXT`): File default username from info DB
  - `groupname` (`TEXT`): File default groupname from info DB
  - `mode` (`TEXT`): File permissions mode from info DB
  - `size` (`BIGINT`): Expected file size in bytes from RPM info DB
  - `sha256` (`TEXT`): SHA256 file digest from RPM info DB

#### `pacman_packages`
- **Source**: `specs/linux/pacman_packages.table`
- **Attributes**: `cacheable=True`
- **Description**: Packages installed by the pacman package manager.
- **Columns**:
  - `name` (`TEXT`, `INDEX`): Package name
  - `version` (`TEXT`): Package version, including epoch and release
  - `source` (`TEXT`): Name of the base package this package was built from
  - `description` (`TEXT`): Package description
  - `url` (`TEXT`): Upstream project URL
  - `licenses` (`TEXT`): Comma separated list of licenses
  - `groups` (`TEXT`): Comma separated list of groups the package belongs to
  - `arch` (`TEXT`): Package architecture
  - `size` (`BIGINT`): Installed size of the package in bytes
  - `packager` (`TEXT`): Person or process that built the package
  - `build_time` (`BIGINT`): Unix time when the package was built
  - `install_time` (`BIGINT`): Unix time when the package was installed
  - `install_reason` (`TEXT`): Either 'explicit' if the package was installed directly, or 'dependency' if it was installed to satisfy another package
  - `validation` (`TEXT`): Comma separated list of methods used to validate the package, for example 'sha256' or 'pgp'
  - `dbpath` (`TEXT`, `ADDITIONAL`, `OPTIMIZED`): pacman database path. Defaults to /var/lib/pacman

#### `snap_packages`
- **Source**: `specs/linux/snap_packages.table`
- **Attributes**: `cacheable=True`
- **Description**: Installed snap packages.
- **Columns**:
  - `name` (`TEXT`, `INDEX`): Package name
  - `version` (`TEXT`): Package version
  - `summary` (`TEXT`): One-line summary
  - `description` (`TEXT`): Long description
  - `type` (`TEXT`): Snap type (app, base, kernel, gadget, snapd)
  - `confinement` (`TEXT`): Confinement policy (strict, devmode, classic)
  - `base` (`TEXT`): Base snap this snap is built on
  - `license` (`TEXT`): SPDX license expression
  - `grade` (`TEXT`): Grade (stable, devel)
  - `architectures` (`TEXT`): Comma-separated list of supported architectures
  - `revision` (`TEXT`): Installed revision number
  - `channel` (`TEXT`): Tracking channel (e.g. stable, beta, edge)
  - `snap_id` (`TEXT`): Snap Store identifier

#### `portage_keywords`
- **Source**: `specs/linux/portage_keywords.table`
- **Description**: A summary about portage configurations like keywords, mask and unmask.
- **Columns**:
  - `package` (`TEXT`): Package name
  - `version` (`TEXT`): The version which are affected by the use flags, empty means all
  - `keyword` (`TEXT`): The keyword applied to the package
  - `mask` (`INTEGER`): If the package is masked
  - `unmask` (`INTEGER`): If the package is unmasked

#### `portage_packages`
- **Source**: `specs/linux/portage_packages.table`
- **Description**: List of currently installed packages.
- **Columns**:
  - `package` (`TEXT`): Package name
  - `version` (`TEXT`): The version which are affected by the use flags, empty means all
  - `slot` (`TEXT`): The slot used by package
  - `build_time` (`BIGINT`): Unix time when package was built
  - `repository` (`TEXT`): From which repository the ebuild was used
  - `eapi` (`BIGINT`): The eapi for the ebuild
  - `size` (`BIGINT`): The size of the package
  - `world` (`INTEGER`): If package is in the world file

#### `portage_use`
- **Source**: `specs/linux/portage_use.table`
- **Description**: List of enabled portage USE values for specific package.
- **Columns**:
  - `package` (`TEXT`): Package name
  - `version` (`TEXT`): The version of the installed package
  - `use` (`TEXT`): USE flag which has been enabled for package

#### `homebrew_packages`
- **Source**: `specs/posix/homebrew_packages.table`
- **Attributes**: `cacheable=True`
- **Description**: The installed homebrew package database.
- **Columns**:
  - `name` (`TEXT`): Package name
  - `path` (`TEXT`): Package install path
  - `version` (`TEXT`): Current 'linked' version
  - `type` (`TEXT`): Package type ('formula' or 'cask')
  - `auto_updates` (`INTEGER`): 1 if the cask auto-updates otherwise 0
  - `app_name` (`TEXT`): Name of the installed App (for Casks)
  - `prefix` (`TEXT`, `ADDITIONAL`, `OPTIMIZED`, `HIDDEN`): Homebrew install prefix

#### `npm_packages`
- **Source**: `specs/npm_packages.table`
- **Description**: Node packages installed in a system.
- **Columns**:
  - `name` (`TEXT`): Package display name
  - `version` (`TEXT`): Package-supplied version
  - `description` (`TEXT`): Package-supplied description
  - `author` (`TEXT`): Package-supplied author
  - `license` (`TEXT`): License under which package is launched
  - `homepage` (`TEXT`): Package supplied homepage
  - `path` (`TEXT`): Path at which this module resides
  - `directory` (`TEXT`, `INDEX`, `OPTIMIZED`): Directory where node_modules are located
  - `depth` (`INTEGER`): Nesting depth of the package (0 = direct dependency)
  - `max_depth` (`INTEGER`, `ADDITIONAL`, `HIDDEN`): Maximum depth to search for nested packages (default 100, -1 = unlimited)
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace
  - `mount_namespace_id` (`TEXT`, `HIDDEN`, `LINUX`): Mount namespace id

#### `python_packages`
- **Source**: `specs/python_packages.table`
- **Attributes**: `user_data=True`
- **Description**: Python packages installed in a system.
- **Columns**:
  - `name` (`TEXT`): Package display name
  - `uid` (`BIGINT`, `INDEX`): The local user that owns the python package
  - `version` (`TEXT`): Package-supplied version
  - `summary` (`TEXT`): Package-supplied summary
  - `author` (`TEXT`): Optional package author
  - `license` (`TEXT`): License under which package is launched
  - `path` (`TEXT`): Path at which this module resides
  - `directory` (`TEXT`, `INDEX`, `OPTIMIZED`): Directory where Python modules are located
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

---

### Category 9: Security Mandatory Access Control (AppArmor, SELinux), Certificates, YARA & EDR (6 Tables)

#### `apparmor_profiles`
- **Source**: `specs/linux/apparmor_profiles.table`
- **Description**: Track active AppArmor profiles.
- **Columns**:
  - `path` (`TEXT`, `INDEX`): Unique, aa-status compatible, policy identifier.
  - `name` (`TEXT`): Policy name.
  - `attach` (`TEXT`): Which executable(s) a profile will attach to.
  - `mode` (`TEXT`): How the policy is applied.
  - `sha1` (`TEXT`): A unique hash that identifies this policy.
  - `sha256` (`TEXT`): A unique hash that identifies this policy.

#### `selinux_settings`
- **Source**: `specs/linux/selinux_settings.table`
- **Description**: Track active SELinux settings.
- **Columns**:
  - `scope` (`TEXT`): Where the key is located inside the SELinuxFS mount point.
  - `key` (`TEXT`): Key or class name.
  - `value` (`TEXT`): Active value.

#### `certificates`
- **Source**: `specs/certificates.table`
- **Attributes**: `cacheable=True`
- **Description**: Certificate Authorities installed in Keychains/ca-bundles.
- **Columns**:
  - `common_name` (`TEXT`): Certificate CommonName
  - `subject` (`TEXT`): Certificate distinguished name (deprecated, use subject2)
  - `subject2` (`TEXT`): Certificate distinguished name
  - `issuer` (`TEXT`): Certificate issuer distinguished name (deprecated, use issuer2)
  - `issuer2` (`TEXT`): Certificate issuer distinguished name
  - `ca` (`INTEGER`): 1 if CA: true (certificate is an authority) else 0
  - `self_signed` (`INTEGER`): 1 if self-signed, else 0
  - `not_valid_before` (`DATETIME`): Lower bound of valid date
  - `not_valid_after` (`DATETIME`): Certificate expiration data
  - `signing_algorithm` (`TEXT`): Signing algorithm used
  - `key_algorithm` (`TEXT`): Key algorithm used
  - `key_strength` (`TEXT`): Key size used for RSA/DSA, or curve name
  - `key_usage` (`TEXT`): Certificate key usage and extended key usage
  - `subject_key_id` (`TEXT`): SKID an optionally included SHA1
  - `authority_key_id` (`TEXT`): AKID an optionally included SHA1
  - `sha1` (`TEXT`): SHA1 hash of the raw certificate contents
  - `path` (`TEXT`, `ADDITIONAL`, `OPTIMIZED`): Path to Keychain or PEM bundle
  - `serial` (`TEXT`): Certificate serial number

#### `yara_file` (alias: `yara`)
- **Source**: `specs/yara_file.table`
- **Required `WHERE` Constraints**: Must provide `path` AND one of `sig_group`, `sigfile`, `sigrule`, or `sigurl`.
- **Description**: Triggers one-off YARA query for files at the specified path. Additionally requires one of `sig_group`, `sigfile`, or `sigrule`.
- **Columns**:
  - `path` (`TEXT`, `REQUIRED`, `INDEX`): The path scanned
  - `matches` (`TEXT`): List of YARA matches
  - `count` (`INTEGER`): Number of YARA matches
  - `sig_group` (`TEXT`, `ADDITIONAL`): Signature group used
  - `sigfile` (`TEXT`, `ADDITIONAL`): Signature file used
  - `sigrule` (`TEXT`, `ADDITIONAL`, `HIDDEN`): Signature strings used
  - `strings` (`TEXT`): Matching strings
  - `tags` (`TEXT`): Matching tags
  - `sigurl` (`TEXT`, `ADDITIONAL`, `HIDDEN`): Signature url
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `yara_process`
- **Source**: `specs/yara_process.table`
- **Required `WHERE` Constraints**: Must provide `pid` AND one of `sig_group`, `sigfile`, `sigrule`, or `sigurl`.
- **Description**: Triggers one-off YARA query for process memory of the specified pid. Additionally requires one of `sig_group`, `sigfile`, or `sigrule`.
- **Columns**:
  - `pid` (`INTEGER`, `REQUIRED`, `INDEX`): The pid scanned (process memory)
  - `matches` (`TEXT`): List of YARA matches
  - `count` (`INTEGER`): Number of YARA matches
  - `sig_group` (`TEXT`, `ADDITIONAL`): Signature group used
  - `sigfile` (`TEXT`, `ADDITIONAL`): Signature file used
  - `sigrule` (`TEXT`, `ADDITIONAL`, `HIDDEN`): Signature strings used
  - `strings` (`TEXT`): Matching strings
  - `tags` (`TEXT`): Matching tags
  - `sigurl` (`TEXT`, `ADDITIONAL`, `HIDDEN`): Signature url
  - `pid_with_namespace` (`INTEGER`, `ADDITIONAL`, `HIDDEN`, `LINUX`): Pids that contain a namespace

#### `carbon_black_info` (alias: `cb_info`)
- **Source**: `specs/carbon_black_info.table`
- **Description**: Returns info about a Carbon Black sensor install.
- **Columns**:
  - `sensor_id` (`INTEGER`): Sensor ID of the Carbon Black sensor
  - `config_name` (`TEXT`): Sensor group
  - `collect_store_files` (`INTEGER`): If the sensor is configured to send back binaries to the Carbon Black server
  - `collect_module_loads` (`INTEGER`): If the sensor is configured to capture module loads
  - `collect_module_info` (`INTEGER`): If the sensor is configured to collect metadata of binaries
  - `collect_file_mods` (`INTEGER`): If the sensor is configured to collect file modification events
  - `collect_reg_mods` (`INTEGER`): If the sensor is configured to collect registry modification events
  - `collect_net_conns` (`INTEGER`): If the sensor is configured to collect network connections
  - `collect_processes` (`INTEGER`): If the sensor is configured to process events
  - `collect_cross_processes` (`INTEGER`): If the sensor is configured to cross process events
  - `collect_emet_events` (`INTEGER`): If the sensor is configured to EMET events
  - `collect_data_file_writes` (`INTEGER`): If the sensor is configured to collect non binary file writes
  - `collect_process_user_context` (`INTEGER`): If the sensor is configured to collect the user running a process
  - `collect_sensor_operations` (`INTEGER`): Unknown
  - `log_file_disk_quota_mb` (`INTEGER`): Event file disk quota in MB
  - `log_file_disk_quota_percentage` (`INTEGER`): Event file disk quota in a percentage
  - `protection_disabled` (`INTEGER`): If the sensor is configured to report tamper events
  - `sensor_ip_addr` (`TEXT`): IP address of the sensor
  - `sensor_backend_server` (`TEXT`): Carbon Black server
  - `event_queue` (`INTEGER`): Size in bytes of Carbon Black event files on disk
  - `binary_queue` (`INTEGER`): Size in bytes of binaries waiting to be sent to Carbon Black server

---

### Category 10: Hardware, PCI, USB, ACPI, SMBIOS & MSR (7 Tables)

#### `pci_devices`
- **Source**: `specs/posix/pci_devices.table`
- **Description**: PCI devices active on the host system.
- **Columns**:
  - `pci_slot` (`TEXT`): PCI Device used slot
  - `pci_class` (`TEXT`): PCI Device class
  - `driver` (`TEXT`): PCI Device used driver
  - `vendor` (`TEXT`): PCI Device vendor
  - `vendor_id` (`TEXT`): Hex encoded PCI Device vendor identifier
  - `model` (`TEXT`): PCI Device model
  - `model_id` (`TEXT`): Hex encoded PCI Device model identifier
  - `pci_class_id` (`TEXT`, `LINUX`): PCI Device class ID in hex format
  - `pci_subclass_id` (`TEXT`, `LINUX`): PCI Device subclass in hex format
  - `pci_subclass` (`TEXT`, `LINUX`): PCI Device subclass
  - `subsystem_vendor_id` (`TEXT`, `LINUX`): Vendor ID of PCI device subsystem
  - `subsystem_vendor` (`TEXT`, `LINUX`): Vendor of PCI device subsystem
  - `subsystem_model_id` (`TEXT`, `LINUX`): Model ID of PCI device subsystem
  - `subsystem_model` (`TEXT`, `LINUX`): Device description of PCI device subsystem

#### `usb_devices`
- **Source**: `specs/posix/usb_devices.table`
- **Description**: USB devices that are actively plugged into the host system.
- **Columns**:
  - `usb_address` (`INTEGER`): USB Device used address
  - `usb_port` (`INTEGER`): USB Device used port
  - `vendor` (`TEXT`): USB Device vendor string
  - `vendor_id` (`TEXT`): Hex encoded USB Device vendor identifier
  - `version` (`TEXT`): USB Device version number
  - `model` (`TEXT`): USB Device model string
  - `model_id` (`TEXT`): Hex encoded USB Device model identifier
  - `serial` (`TEXT`): USB Device serial connection
  - `class` (`TEXT`): USB Device class
  - `subclass` (`TEXT`): USB Device subclass
  - `protocol` (`TEXT`): USB Device protocol
  - `removable` (`INTEGER`): 1 If USB device is removable else 0

#### `acpi_tables`
- **Source**: `specs/posix/acpi_tables.table`
- **Description**: Firmware ACPI functional table common metadata and content.
- **Columns**:
  - `name` (`TEXT`): ACPI table name
  - `size` (`INTEGER`): Size of compiled table data
  - `md5` (`TEXT`): MD5 hash of table content

#### `smbios_tables`
- **Source**: `specs/posix/smbios_tables.table`
- **Description**: BIOS (DMI) structure common details and content.
- **Columns**:
  - `number` (`INTEGER`): Table entry number
  - `type` (`INTEGER`): Table entry type
  - `description` (`TEXT`): Table entry description
  - `handle` (`INTEGER`): Table entry handle
  - `header_size` (`INTEGER`): Header size in bytes
  - `size` (`INTEGER`): Table entry size in bytes
  - `md5` (`TEXT`): MD5 hash of table entry

#### `oem_strings`
- **Source**: `specs/posix/oem_strings.table`
- **Description**: OEM defined strings retrieved from SMBIOS.
- **Columns**:
  - `handle` (`TEXT`): Handle, or instance number, associated with the Type 11 structure
  - `number` (`INTEGER`): The string index of the structure
  - `value` (`TEXT`): The value of the OEM string

#### `intel_me_info`
- **Source**: `specs/linwin/intel_me_info.table`
- **Description**: Intel ME/CSE Info.
- **Columns**:
  - `version` (`TEXT`): Intel ME version

#### `msr`
- **Source**: `specs/linux/msr.table`
- **Description**: Various pieces of data stored in the model specific register per processor. NOTE: the msr kernel module must be enabled, and osquery must be run as root.
- **Columns**:
  - `processor_number` (`BIGINT`): The processor number as reported in /proc/cpuinfo
  - `turbo_disabled` (`BIGINT`): Whether the turbo feature is disabled.
  - `turbo_ratio_limit` (`BIGINT`): The turbo feature ratio limit.
  - `platform_info` (`BIGINT`): Platform information.
  - `perf_ctl` (`BIGINT`): Performance setting for the processor.
  - `perf_status` (`BIGINT`): Performance status for the processor.
  - `feature_control` (`BIGINT`): Bitfield controlling enabled features.
  - `rapl_power_limit` (`BIGINT`): Run Time Average Power Limiting power limit.
  - `rapl_energy_status` (`BIGINT`): Run Time Average Power Limiting energy status.
  - `rapl_power_units` (`BIGINT`): Run Time Average Power Limiting power units.

---

### Category 11: Containers & Virtualization — Docker & LXD (28 Tables)

#### `docker_info`
- **Source**: `specs/posix/docker_info.table`
- **Attributes**: `cacheable=True`
- **Description**: Docker system information.
- **Columns**:
  - `id` (`TEXT`): Docker system ID
  - `containers` (`INTEGER`): Total number of containers
  - `containers_running` (`INTEGER`): Number of containers currently running
  - `containers_paused` (`INTEGER`): Number of containers in paused state
  - `containers_stopped` (`INTEGER`): Number of containers in stopped state
  - `images` (`INTEGER`): Number of images
  - `storage_driver` (`TEXT`): Storage driver
  - `memory_limit` (`INTEGER`): 1 if memory limit support is enabled. 0 otherwise
  - `swap_limit` (`INTEGER`): 1 if swap limit support is enabled. 0 otherwise
  - `kernel_memory` (`INTEGER`): 1 if kernel memory limit support is enabled. 0 otherwise
  - `cpu_cfs_period` (`INTEGER`): 1 if CPU Completely Fair Scheduler (CFS) period support is enabled. 0 otherwise
  - `cpu_cfs_quota` (`INTEGER`): 1 if CPU Completely Fair Scheduler (CFS) quota support is enabled. 0 otherwise
  - `cpu_shares` (`INTEGER`): 1 if CPU share weighting support is enabled. 0 otherwise
  - `cpu_set` (`INTEGER`): 1 if CPU set selection support is enabled. 0 otherwise
  - `ipv4_forwarding` (`INTEGER`): 1 if IPv4 forwarding is enabled. 0 otherwise
  - `bridge_nf_iptables` (`INTEGER`): 1 if bridge netfilter iptables is enabled. 0 otherwise
  - `bridge_nf_ip6tables` (`INTEGER`): 1 if bridge netfilter ip6tables is enabled. 0 otherwise
  - `oom_kill_disable` (`INTEGER`): 1 if Out-of-memory kill is disabled. 0 otherwise
  - `logging_driver` (`TEXT`): Logging driver
  - `cgroup_driver` (`TEXT`): Control groups driver
  - `kernel_version` (`TEXT`): Kernel version
  - `os` (`TEXT`): Operating system
  - `os_type` (`TEXT`): Operating system type
  - `architecture` (`TEXT`): Hardware architecture
  - `cpus` (`INTEGER`): Number of CPUs
  - `memory` (`BIGINT`): Total memory
  - `http_proxy` (`TEXT`): HTTP proxy
  - `https_proxy` (`TEXT`): HTTPS proxy
  - `no_proxy` (`TEXT`): Comma-separated list of domain extensions proxy should not be used for
  - `name` (`TEXT`): Name of the docker host
  - `server_version` (`TEXT`): Server version
  - `root_dir` (`TEXT`): Docker root directory

#### `docker_version`
- **Source**: `specs/posix/docker_version.table`
- **Attributes**: `cacheable=True`
- **Description**: Docker version information.
- **Columns**:
  - `version` (`TEXT`): Docker version
  - `api_version` (`TEXT`): API version
  - `min_api_version` (`TEXT`): Minimum API version supported
  - `git_commit` (`TEXT`): Docker build git commit
  - `go_version` (`TEXT`): Go version
  - `os` (`TEXT`): Operating system
  - `arch` (`TEXT`): Hardware architecture
  - `kernel_version` (`TEXT`): Kernel version
  - `build_time` (`TEXT`): Build time

#### `docker_containers`
- **Source**: `specs/posix/docker_containers.table`
- **Description**: Docker containers information.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Container ID
  - `name` (`TEXT`, `INDEX`): Container name
  - `image` (`TEXT`): Docker image (name) used to launch this container
  - `image_id` (`TEXT`): Docker image ID
  - `command` (`TEXT`): Command with arguments
  - `created` (`BIGINT`): Time of creation as UNIX time
  - `state` (`TEXT`): Container state (created, restarting, running, removing, paused, exited, dead)
  - `status` (`TEXT`): Container status information
  - `pid` (`BIGINT`): Identifier of the initial process
  - `path` (`TEXT`): Container path
  - `config_entrypoint` (`TEXT`): Container entrypoint(s)
  - `started_at` (`TEXT`): Container start time as string
  - `finished_at` (`TEXT`): Container finish time as string
  - `privileged` (`INTEGER`): Is the container privileged
  - `security_options` (`TEXT`): List of container security options
  - `env_variables` (`TEXT`): Container environmental variables
  - `readonly_rootfs` (`INTEGER`): Is the root filesystem mounted as read only
  - `cgroup_namespace` (`TEXT`, `LINUX`): cgroup namespace
  - `ipc_namespace` (`TEXT`, `LINUX`): IPC namespace
  - `mnt_namespace` (`TEXT`, `LINUX`): Mount namespace
  - `net_namespace` (`TEXT`, `LINUX`): Network namespace
  - `pid_namespace` (`TEXT`, `LINUX`): PID namespace
  - `user_namespace` (`TEXT`, `LINUX`): User namespace
  - `uts_namespace` (`TEXT`, `LINUX`): UTS namespace

#### `docker_container_envs`
- **Source**: `specs/posix/docker_container_envs.table`
- **Description**: Docker container environment variables.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Container ID
  - `key` (`TEXT`): Environment variable name
  - `value` (`TEXT`): Environment variable value

#### `docker_container_fs_changes`
- **Source**: `specs/posix/docker_container_fs_changes.table`
- **Required `WHERE` Constraints**: Must provide `id` in `WHERE`.
- **Description**: Changes to files or directories on container's filesystem.
- **Columns**:
  - `id` (`TEXT`, `REQUIRED`, `INDEX`): Container ID
  - `path` (`TEXT`): File or directory path relative to rootfs
  - `change_type` (`TEXT`): Type of change: C:Modified, A:Added, D:Deleted

#### `docker_container_labels`
- **Source**: `specs/posix/docker_container_labels.table`
- **Description**: Docker container labels.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Container ID
  - `key` (`TEXT`, `INDEX`): Label key
  - `value` (`TEXT`): Optional label value

#### `docker_container_mounts`
- **Source**: `specs/posix/docker_container_mounts.table`
- **Description**: Docker container mounts.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Container ID
  - `type` (`TEXT`): Type of mount (bind, volume)
  - `name` (`TEXT`, `INDEX`): Optional mount name
  - `source` (`TEXT`): Source path on host
  - `destination` (`TEXT`): Destination path inside container
  - `driver` (`TEXT`): Driver providing the mount
  - `mode` (`TEXT`): Mount options (rw, ro)
  - `rw` (`INTEGER`): 1 if read/write. 0 otherwise
  - `propagation` (`TEXT`): Mount propagation

#### `docker_container_networks`
- **Source**: `specs/posix/docker_container_networks.table`
- **Description**: Docker container networks.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Container ID
  - `name` (`TEXT`, `INDEX`): Network name
  - `network_id` (`TEXT`): Network ID
  - `endpoint_id` (`TEXT`): Endpoint ID
  - `gateway` (`TEXT`): Gateway
  - `ip_address` (`TEXT`): IP address
  - `ip_prefix_len` (`INTEGER`): IP subnet prefix length
  - `ipv6_gateway` (`TEXT`): IPv6 gateway
  - `ipv6_address` (`TEXT`): IPv6 address
  - `ipv6_prefix_len` (`INTEGER`): IPv6 subnet prefix length
  - `mac_address` (`TEXT`): MAC address

#### `docker_container_ports`
- **Source**: `specs/posix/docker_container_ports.table`
- **Description**: Docker container ports.
- **Columns**:
  - `id` (`TEXT`, `ADDITIONAL`): Container ID
  - `type` (`TEXT`): Protocol (tcp, udp)
  - `port` (`INTEGER`): Port inside the container
  - `host_ip` (`TEXT`): Host IP address on which public port is listening
  - `host_port` (`INTEGER`): Host port

#### `docker_container_processes`
- **Source**: `specs/posix/docker_container_processes.table`
- **Required `WHERE` Constraints**: Must provide `id` in `WHERE`.
- **Description**: Docker container processes.
- **Columns**:
  - `id` (`TEXT`, `REQUIRED`, `INDEX`): Container ID
  - `pid` (`BIGINT`, `INDEX`): Process ID
  - `name` (`TEXT`): The process path or shorthand argv[0]
  - `cmdline` (`TEXT`): Complete argv
  - `state` (`TEXT`): Process state
  - `uid` (`BIGINT`): User ID
  - `gid` (`BIGINT`): Group ID
  - `euid` (`BIGINT`): Effective user ID
  - `egid` (`BIGINT`): Effective group ID
  - `suid` (`BIGINT`): Saved user ID
  - `sgid` (`BIGINT`): Saved group ID
  - `wired_size` (`BIGINT`): Bytes of unpageable memory used by process
  - `resident_size` (`BIGINT`): Bytes of private memory used by process
  - `total_size` (`BIGINT`): Total virtual memory size
  - `start_time` (`BIGINT`): Process start in seconds since boot (non-sleeping)
  - `parent` (`BIGINT`): Process parent's PID
  - `pgroup` (`BIGINT`): Process group
  - `threads` (`INTEGER`): Number of threads used by process
  - `nice` (`INTEGER`): Process nice level (-20 to 20, default 0)
  - `user` (`TEXT`): User name
  - `time` (`TEXT`): Cumulative CPU time. [DD-]HH:MM:SS format
  - `cpu` (`DOUBLE`): CPU utilization as percentage
  - `mem` (`DOUBLE`): Memory utilization as percentage

#### `docker_container_stats`
- **Source**: `specs/posix/docker_container_stats.table`
- **Required `WHERE` Constraints**: Must provide `id` in `WHERE`.
- **Description**: Docker container statistics. Queries on this table take at least one second.
- **Columns**:
  - `id` (`TEXT`, `REQUIRED`, `INDEX`): Container ID
  - `name` (`TEXT`, `INDEX`): Container name
  - `pids` (`INTEGER`): Number of processes
  - `read` (`BIGINT`): UNIX time when stats were read
  - `preread` (`BIGINT`): UNIX time when stats were last read
  - `interval` (`BIGINT`): Difference between read and preread in nano-seconds
  - `disk_read` (`BIGINT`): Total disk read bytes
  - `disk_write` (`BIGINT`): Total disk write bytes
  - `num_procs` (`INTEGER`): Number of processors
  - `cpu_total_usage` (`BIGINT`): Total CPU usage
  - `cpu_kernelmode_usage` (`BIGINT`): CPU kernel mode usage
  - `cpu_usermode_usage` (`BIGINT`): CPU user mode usage
  - `system_cpu_usage` (`BIGINT`): CPU system usage
  - `online_cpus` (`INTEGER`): Online CPUs
  - `pre_cpu_total_usage` (`BIGINT`): Last read total CPU usage
  - `pre_cpu_kernelmode_usage` (`BIGINT`): Last read CPU kernel mode usage
  - `pre_cpu_usermode_usage` (`BIGINT`): Last read CPU user mode usage
  - `pre_system_cpu_usage` (`BIGINT`): Last read CPU system usage
  - `pre_online_cpus` (`INTEGER`): Last read online CPUs
  - `memory_usage` (`BIGINT`): Memory usage
  - `memory_cached` (`BIGINT`): Memory cached
  - `memory_inactive_file` (`BIGINT`): Memory inactive file
  - `memory_total_inactive_file` (`BIGINT`): Memory total inactive file
  - `memory_max_usage` (`BIGINT`): Memory maximum usage
  - `memory_limit` (`BIGINT`): Memory limit
  - `network_rx_bytes` (`BIGINT`): Total network bytes read
  - `network_tx_bytes` (`BIGINT`): Total network bytes transmitted

#### `docker_images`
- **Source**: `specs/posix/docker_images.table`
- **Description**: Docker images information.
- **Columns**:
  - `id` (`TEXT`): Image ID
  - `created` (`BIGINT`): Time of creation as UNIX time
  - `size_bytes` (`BIGINT`): Size of image in bytes
  - `tags` (`TEXT`): Comma-separated list of repository tags

#### `docker_image_history`
- **Source**: `specs/posix/docker_image_history.table`
- **Description**: Docker image history information.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Image ID
  - `created` (`BIGINT`): Time of creation as UNIX time
  - `size` (`BIGINT`): Size of instruction in bytes
  - `created_by` (`TEXT`): Created by instruction
  - `tags` (`TEXT`): Comma-separated list of tags
  - `comment` (`TEXT`): Instruction comment

#### `docker_image_labels`
- **Source**: `specs/posix/docker_image_labels.table`
- **Description**: Docker image labels.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Image ID
  - `key` (`TEXT`): Label key
  - `value` (`TEXT`): Optional label value

#### `docker_image_layers`
- **Source**: `specs/posix/docker_image_layers.table`
- **Description**: Docker image layers information.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Image ID
  - `layer_id` (`TEXT`): Layer ID
  - `layer_order` (`INTEGER`): Layer Order (1 = base layer)

#### `docker_networks`
- **Source**: `specs/posix/docker_networks.table`
- **Description**: Docker networks information.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Network ID
  - `name` (`TEXT`): Network name
  - `driver` (`TEXT`): Network driver
  - `created` (`BIGINT`): Time of creation as UNIX time
  - `enable_ipv6` (`INTEGER`): 1 if IPv6 is enabled on this network. 0 otherwise
  - `subnet` (`TEXT`): Network subnet
  - `gateway` (`TEXT`): Network gateway

#### `docker_network_labels`
- **Source**: `specs/posix/docker_network_labels.table`
- **Description**: Docker network labels.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Network ID
  - `key` (`TEXT`): Label key
  - `value` (`TEXT`): Optional label value

#### `docker_volumes`
- **Source**: `specs/posix/docker_volumes.table`
- **Description**: Docker volumes information.
- **Columns**:
  - `name` (`TEXT`, `INDEX`): Volume name
  - `driver` (`TEXT`): Volume driver
  - `mount_point` (`TEXT`): Mount point
  - `type` (`TEXT`): Volume type

#### `docker_volume_labels`
- **Source**: `specs/posix/docker_volume_labels.table`
- **Description**: Docker volume labels.
- **Columns**:
  - `name` (`TEXT`, `INDEX`): Volume name
  - `key` (`TEXT`, `INDEX`): Label key
  - `value` (`TEXT`): Optional label value

#### `lxd_cluster`
- **Source**: `specs/linux/lxd_cluster.table`
- **Description**: LXD cluster information.
- **Columns**:
  - `server_name` (`TEXT`): Name of the LXD server node
  - `enabled` (`INTEGER`): Whether clustering enabled (1) or not (0) on this node
  - `member_config_entity` (`TEXT`): Type of configuration parameter for this node
  - `member_config_name` (`TEXT`): Name of configuration parameter
  - `member_config_key` (`TEXT`): Config key
  - `member_config_value` (`TEXT`): Config value
  - `member_config_description` (`TEXT`): Config description

#### `lxd_cluster_members`
- **Source**: `specs/linux/lxd_cluster_members.table`
- **Description**: LXD cluster members information.
- **Columns**:
  - `server_name` (`TEXT`): Name of the LXD server node
  - `url` (`TEXT`): URL of the node
  - `database` (`INTEGER`): Whether the server is a database node (1) or not (0)
  - `status` (`TEXT`): Status of the node (Online/Offline)
  - `message` (`TEXT`): Message from the node (Online/Offline)

#### `lxd_instances`
- **Source**: `specs/linux/lxd_instances.table`
- **Description**: LXD instances information.
- **Columns**:
  - `name` (`TEXT`, `INDEX`): Instance name
  - `status` (`TEXT`): Instance state (running, stopped, etc.)
  - `stateful` (`INTEGER`): Whether the instance is stateful(1) or not(0)
  - `ephemeral` (`INTEGER`): Whether the instance is ephemeral(1) or not(0)
  - `created_at` (`TEXT`): ISO time of creation
  - `base_image` (`TEXT`): ID of image used to launch this instance
  - `architecture` (`TEXT`): Instance architecture
  - `os` (`TEXT`): The OS of this instance
  - `description` (`TEXT`): Instance description
  - `pid` (`INTEGER`): Instance's process ID
  - `processes` (`INTEGER`): Number of processes running inside this instance

#### `lxd_instance_config`
- **Source**: `specs/linux/lxd_instance_config.table`
- **Required `WHERE` Constraints**: Must provide `name` in `WHERE`.
- **Description**: LXD instance configuration information.
- **Columns**:
  - `name` (`TEXT`, `REQUIRED`, `INDEX`): Instance name
  - `key` (`TEXT`): Configuration parameter name
  - `value` (`TEXT`): Configuration parameter value

#### `lxd_instance_devices`
- **Source**: `specs/linux/lxd_instance_devices.table`
- **Required `WHERE` Constraints**: Must provide `name` in `WHERE`.
- **Description**: LXD instance devices information.
- **Columns**:
  - `name` (`TEXT`, `REQUIRED`, `INDEX`): Instance name
  - `device` (`TEXT`): Name of the device
  - `device_type` (`TEXT`): Device type
  - `key` (`TEXT`): Device info param name
  - `value` (`TEXT`): Device info param value

#### `lxd_images`
- **Source**: `specs/linux/lxd_images.table`
- **Description**: LXD images information.
- **Columns**:
  - `id` (`TEXT`, `INDEX`): Image ID
  - `architecture` (`TEXT`): Target architecture for the image
  - `os` (`TEXT`): OS on which image is based
  - `release` (`TEXT`): OS release version on which the image is based
  - `description` (`TEXT`): Image description
  - `aliases` (`TEXT`): Comma-separated list of image aliases
  - `filename` (`TEXT`): Filename of the image file
  - `size` (`BIGINT`): Size of image in bytes
  - `auto_update` (`INTEGER`): Whether the image auto-updates (1) or not (0)
  - `cached` (`INTEGER`): Whether image is cached (1) or not (0)
  - `public` (`INTEGER`): Whether image is public (1) or not (0)
  - `created_at` (`TEXT`): ISO time of image creation
  - `expires_at` (`TEXT`): ISO time of image expiration
  - `uploaded_at` (`TEXT`): ISO time of image upload
  - `last_used_at` (`TEXT`): ISO time for the most recent use of this image in terms of container spawn
  - `update_source_server` (`TEXT`): Server for image update
  - `update_source_protocol` (`TEXT`): Protocol used for image information update and image import from source server
  - `update_source_certificate` (`TEXT`): Certificate for update source server
  - `update_source_alias` (`TEXT`): Alias of image at update source server

#### `lxd_networks`
- **Source**: `specs/linux/lxd_networks.table`
- **Description**: LXD network information.
- **Columns**:
  - `name` (`TEXT`): Name of the network
  - `type` (`TEXT`): Type of network
  - `managed` (`INTEGER`): 1 if network created by LXD, 0 otherwise
  - `ipv4_address` (`TEXT`): IPv4 address
  - `ipv6_address` (`TEXT`): IPv6 address
  - `used_by` (`TEXT`): URLs for containers using this network
  - `bytes_received` (`BIGINT`): Number of bytes received on this network
  - `bytes_sent` (`BIGINT`): Number of bytes sent on this network
  - `packets_received` (`BIGINT`): Number of packets received on this network
  - `packets_sent` (`BIGINT`): Number of packets sent on this network
  - `hwaddr` (`TEXT`): Hardware address for this network
  - `state` (`TEXT`): Network status
  - `mtu` (`INTEGER`): MTU size

#### `lxd_storage_pools`
- **Source**: `specs/linux/lxd_storage_pools.table`
- **Description**: LXD storage pool information.
- **Columns**:
  - `name` (`TEXT`): Name of the storage pool
  - `driver` (`TEXT`): Storage driver
  - `source` (`TEXT`): Storage pool source
  - `size` (`TEXT`): Size of the storage pool
  - `space_used` (`BIGINT`): Storage space used in bytes
  - `space_total` (`BIGINT`): Total available storage space in bytes for this storage pool
  - `inodes_used` (`BIGINT`): Number of inodes used
  - `inodes_total` (`BIGINT`): Total number of inodes available in this storage pool

#### `lxd_certificates`
- **Source**: `specs/linux/lxd_certificates.table`
- **Description**: LXD certificates information.
- **Columns**:
  - `name` (`TEXT`): Name of the certificate
  - `type` (`TEXT`): Type of the certificate
  - `fingerprint` (`TEXT`): SHA256 hash of the certificate
  - `certificate` (`TEXT`): Certificate content

---

### Category 12: Events & Audit Monitoring (`_events` Subscriber Tables) (11 Tables)

#### `process_events`
- **Source**: `specs/posix/process_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: Track time/action process executions.
- **Columns**:
  - `pid` (`BIGINT`): Process (or thread) ID
  - `path` (`TEXT`): Path of executed file
  - `mode` (`TEXT`): File mode permissions
  - `cmdline` (`TEXT`): Command line arguments (argv)
  - `cmdline_size` (`BIGINT`, `HIDDEN`): Actual size (bytes) of command line arguments
  - `env` (`TEXT`, `HIDDEN`, alias: `environment`): Environment variables delimited by spaces
  - `env_count` (`BIGINT`, `HIDDEN`, alias: `environment_count`): Number of environment variables
  - `env_size` (`BIGINT`, `HIDDEN`, alias: `environment_size`): Actual size (bytes) of environment list
  - `cwd` (`TEXT`): The process current working directory
  - `auid` (`BIGINT`): Audit User ID at process start
  - `uid` (`BIGINT`): User ID at process start
  - `euid` (`BIGINT`): Effective user ID at process start
  - `gid` (`BIGINT`): Group ID at process start
  - `egid` (`BIGINT`): Effective group ID at process start
  - `owner_uid` (`BIGINT`): File owner user ID
  - `owner_gid` (`BIGINT`): File owner group ID
  - `atime` (`BIGINT`, alias: `access_time`): File last access in UNIX time
  - `mtime` (`BIGINT`, alias: `modify_time`): File modification in UNIX time
  - `ctime` (`BIGINT`, alias: `change_time`): File last metadata change in UNIX time
  - `btime` (`BIGINT`, alias: `create_time`): File creation in UNIX time
  - `overflows` (`TEXT`, `HIDDEN`): List of structures that overflowed
  - `parent` (`BIGINT`): Process parent's PID, or -1 if cannot be determined.
  - `time` (`BIGINT`, `ADDITIONAL`): Time of execution in UNIX time
  - `uptime` (`BIGINT`): Time of execution in system uptime
  - `eid` (`TEXT`, `HIDDEN`): Event ID
  - `fsuid` (`BIGINT`, `LINUX`): Filesystem user ID at process start
  - `suid` (`BIGINT`, `LINUX`): Saved user ID at process start
  - `fsgid` (`BIGINT`, `LINUX`): Filesystem group ID at process start
  - `sgid` (`BIGINT`, `LINUX`): Saved group ID at process start
  - `syscall` (`TEXT`, `LINUX`): Syscall name: fork, vfork, clone, execve, execveat

#### `process_file_events`
- **Source**: `specs/linux/process_file_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: A File Integrity Monitor implementation using the audit service.
- **Columns**:
  - `operation` (`TEXT`): Operation type
  - `pid` (`BIGINT`): Process ID
  - `ppid` (`BIGINT`): Parent process ID
  - `time` (`BIGINT`, `ADDITIONAL`): Time of execution in UNIX time
  - `executable` (`TEXT`): The executable path
  - `partial` (`TEXT`): True if this is a partial event (i.e.: this process existed before we started osquery)
  - `cwd` (`TEXT`): The current working directory of the process
  - `path` (`TEXT`): The path associated with the event
  - `dest_path` (`TEXT`): The canonical path associated with the event
  - `uid` (`TEXT`): The uid of the process performing the action
  - `gid` (`TEXT`): The gid of the process performing the action
  - `auid` (`TEXT`): Audit user ID of the process using the file
  - `euid` (`TEXT`): Effective user ID of the process using the file
  - `egid` (`TEXT`): Effective group ID of the process using the file
  - `fsuid` (`TEXT`): Filesystem user ID of the process using the file
  - `fsgid` (`TEXT`): Filesystem group ID of the process using the file
  - `suid` (`TEXT`): Saved user ID of the process using the file
  - `sgid` (`TEXT`): Saved group ID of the process using the file
  - `uptime` (`BIGINT`): Time of execution in system uptime
  - `eid` (`TEXT`, `HIDDEN`): Event ID

#### `socket_events`
- **Source**: `specs/posix/socket_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: Track network socket bind, connect, and accepts.
- **Columns**:
  - `action` (`TEXT`): The socket action (bind, connect, accept)
  - `pid` (`BIGINT`): Process (or thread) ID
  - `path` (`TEXT`): Path of executed file
  - `fd` (`TEXT`): The file description for the process socket
  - `auid` (`BIGINT`): Audit User ID
  - `family` (`INTEGER`): The Internet protocol family ID
  - `protocol` (`INTEGER`, `HIDDEN`): The network protocol ID
  - `local_address` (`TEXT`): Local address associated with socket
  - `remote_address` (`TEXT`): Remote address associated with socket
  - `local_port` (`INTEGER`): Local network protocol port number
  - `remote_port` (`INTEGER`): Remote network protocol port number
  - `socket` (`TEXT`, `HIDDEN`): The local path (UNIX domain socket only)
  - `time` (`BIGINT`, `ADDITIONAL`): Time of execution in UNIX time
  - `uptime` (`BIGINT`): Time of execution in system uptime
  - `eid` (`TEXT`, `HIDDEN`): Event ID
  - `success` (`INTEGER`, `HIDDEN`): Deprecated. Use the 'status' column instead
  - `status` (`TEXT`, `LINUX`): Either 'succeeded', 'failed', 'in_progress' (connect() on non-blocking socket) or 'no_client' (null accept() on non-blocking socket)

#### `file_events`
- **Source**: `specs/posix/file_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: Track time/action changes to files specified in configuration data.
- **Columns**:
  - `target_path` (`TEXT`): The path associated with the event
  - `category` (`TEXT`): The category of the file defined in the config
  - `action` (`TEXT`): Change action (UPDATE, REMOVE, etc)
  - `transaction_id` (`BIGINT`): ID used during bulk update
  - `inode` (`BIGINT`): Filesystem inode number
  - `uid` (`BIGINT`): Owning user ID
  - `gid` (`BIGINT`): Owning group ID
  - `mode` (`TEXT`): Permission bits
  - `size` (`BIGINT`): Size of file in bytes
  - `atime` (`BIGINT`): Last access time
  - `mtime` (`BIGINT`): Last modification time
  - `ctime` (`BIGINT`): Last status change time
  - `md5` (`TEXT`): The MD5 of the file after change
  - `sha1` (`TEXT`): The SHA1 of the file after change
  - `sha256` (`TEXT`): The SHA256 of the file after change
  - `hashed` (`INTEGER`): 1 if the file was hashed, 0 if not, -1 if hashing failed
  - `time` (`BIGINT`, `ADDITIONAL`): Time of file event
  - `eid` (`TEXT`, `HIDDEN`): Event ID

#### `user_events`
- **Source**: `specs/posix/user_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: Track user events from the audit framework.
- **Columns**:
  - `uid` (`BIGINT`): User ID
  - `auid` (`BIGINT`): Audit User ID
  - `pid` (`BIGINT`): Process (or thread) ID
  - `message` (`TEXT`): Message from the event
  - `type` (`INTEGER`): The file description for the process socket
  - `path` (`TEXT`): Supplied path from event
  - `address` (`TEXT`): The Internet protocol address or family ID
  - `terminal` (`TEXT`): The network protocol ID
  - `time` (`BIGINT`, `ADDITIONAL`): Time of execution in UNIX time
  - `uptime` (`BIGINT`): Time of execution in system uptime
  - `eid` (`TEXT`, `HIDDEN`): Event ID

#### `hardware_events`
- **Source**: `specs/posix/hardware_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: Hardware (PCI/USB/HID) events from UDEV or IOKit.
- **Columns**:
  - `action` (`TEXT`): Remove, insert, change properties, etc
  - `path` (`TEXT`): Local device path assigned (optional)
  - `type` (`TEXT`): Type of hardware and hardware event
  - `driver` (`TEXT`): Driver claiming the device
  - `vendor` (`TEXT`): Hardware device vendor
  - `vendor_id` (`TEXT`): Hex encoded Hardware vendor identifier
  - `model` (`TEXT`): Hardware device model
  - `model_id` (`TEXT`): Hex encoded Hardware model identifier
  - `serial` (`TEXT`): Device serial (optional)
  - `revision` (`TEXT`): Device revision (optional)
  - `time` (`BIGINT`, `ADDITIONAL`): Time of hardware event
  - `eid` (`TEXT`, `HIDDEN`): Event ID

#### `syslog_events` (alias: `syslog`)
- **Source**: `specs/linux/syslog_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: Track syslog events sent to the configured osquery syslog pipe.
- **Columns**:
  - `time` (`BIGINT`, `ADDITIONAL`): Current unix epoch time
  - `datetime` (`TEXT`): Time known to syslog
  - `host` (`TEXT`): Hostname configured for syslog
  - `severity` (`INTEGER`): Syslog severity
  - `facility` (`TEXT`): Syslog facility
  - `tag` (`TEXT`): The syslog tag
  - `message` (`TEXT`): The syslog message
  - `eid` (`TEXT`, `HIDDEN`): Event ID

#### `apparmor_events`
- **Source**: `specs/linux/apparmor_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: Track AppArmor events.
- **Columns**:
  - `type` (`TEXT`): Event type
  - `message` (`TEXT`): Raw audit message
  - `time` (`BIGINT`, `ADDITIONAL`): Time of execution in UNIX time
  - `uptime` (`BIGINT`): Time of execution in system uptime
  - `eid` (`TEXT`, `HIDDEN`): Event ID
  - `apparmor` (`TEXT`): Apparmor Status like ALLOWED, DENIED etc.
  - `operation` (`TEXT`): Permission requested by the process
  - `parent` (`UNSIGNED_BIGINT`): Parent process PID
  - `profile` (`TEXT`): Apparmor profile name
  - `name` (`TEXT`): Process name
  - `pid` (`UNSIGNED_BIGINT`): Process ID
  - `comm` (`TEXT`): Command-line name of the command that was used to invoke the analyzed process
  - `denied_mask` (`TEXT`): Denied permissions for the process
  - `capname` (`TEXT`): Capability requested by the process
  - `fsuid` (`UNSIGNED_BIGINT`): Filesystem user ID
  - `ouid` (`UNSIGNED_BIGINT`): Object owner's user ID
  - `capability` (`BIGINT`): Capability number
  - `requested_mask` (`TEXT`): Requested access mask
  - `info` (`TEXT`): Additional information
  - `error` (`TEXT`): Error information
  - `namespace` (`TEXT`): AppArmor namespace
  - `label` (`TEXT`): AppArmor label

#### `selinux_events`
- **Source**: `specs/linux/selinux_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: Track SELinux events.
- **Columns**:
  - `type` (`TEXT`): Event type
  - `message` (`TEXT`): Message
  - `time` (`BIGINT`, `ADDITIONAL`): Time of execution in UNIX time
  - `uptime` (`BIGINT`): Time of execution in system uptime
  - `eid` (`TEXT`, `HIDDEN`): Event ID

#### `seccomp_events`
- **Source**: `specs/linux/seccomp_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: A virtual table that tracks seccomp events.
- **Columns**:
  - `time` (`BIGINT`, `ADDITIONAL`): Time of execution in UNIX time
  - `uptime` (`BIGINT`): Time of execution in system uptime
  - `auid` (`UNSIGNED_BIGINT`): Audit user ID (loginuid) of the user who started the analyzed process
  - `uid` (`UNSIGNED_BIGINT`): User ID of the user who started the analyzed process
  - `gid` (`UNSIGNED_BIGINT`): Group ID of the user who started the analyzed process
  - `ses` (`UNSIGNED_BIGINT`): Session ID of the session from which the analyzed process was invoked
  - `pid` (`UNSIGNED_BIGINT`): Process ID
  - `comm` (`TEXT`): Command-line name of the command that was used to invoke the analyzed process
  - `exe` (`TEXT`): The path to the executable that was used to invoke the analyzed process
  - `sig` (`BIGINT`): Signal value sent to process by seccomp
  - `arch` (`TEXT`): Information about the CPU architecture
  - `syscall` (`TEXT`): Type of the system call
  - `compat` (`BIGINT`): Is system call in compatibility mode
  - `ip` (`TEXT`): Instruction pointer value
  - `code` (`TEXT`): The seccomp action

#### `yara_events`
- **Source**: `specs/yara_events.table`
- **Attributes**: `event_subscriber=True`
- **Description**: Track YARA matches for files specified in configuration data.
- **Columns**:
  - `target_path` (`TEXT`): The path scanned
  - `category` (`TEXT`): The category of the file
  - `action` (`TEXT`): Change action (UPDATE, REMOVE, etc)
  - `matches` (`TEXT`): List of YARA matches
  - `count` (`INTEGER`): Number of YARA matches
  - `strings` (`TEXT`): Matching strings
  - `tags` (`TEXT`): Matching tags
  - `time` (`BIGINT`): Time of the scan
  - `eid` (`TEXT`, `HIDDEN`): Event ID

---

### Category 13: Browser, IDE Extensions & Application Metrics (6 Tables)

#### `chrome_extensions`
- **Source**: `specs/chrome_extensions.table`
- **Attributes**: `user_data=True`
- **Description**: Chrome-based browser extensions.
- **Columns**:
  - `browser_type` (`TEXT`): The browser type (Valid values: chrome, chrome_beta, chrome_dev, chrome_canary, chromium, opera, yandex, brave, brave_beta, brave_nightly, edge, edge_beta, edge_dev, edge_canary, vivaldi, arc, dia, comet)
  - `uid` (`BIGINT`, `INDEX`, `OPTIMIZED`): The local user that owns the extension
  - `name` (`TEXT`): Extension display name
  - `profile` (`TEXT`): The name of the Chrome profile that contains this extension
  - `profile_path` (`TEXT`): The profile path
  - `referenced_identifier` (`TEXT`): Extension identifier, as specified by the preferences file. Empty if the extension is not in the profile.
  - `identifier` (`TEXT`): Extension identifier, computed from its manifest. Empty in case of error.
  - `version` (`TEXT`): Extension-supplied version
  - `description` (`TEXT`): Extension-optional description
  - `default_locale` (`TEXT`, alias: `locale`): Default locale supported by extension
  - `current_locale` (`TEXT`): Current locale supported by extension
  - `update_url` (`TEXT`): Extension-supplied update URI
  - `author` (`TEXT`): Optional extension author
  - `persistent` (`INTEGER`): 1 If extension is persistent across all tabs else 0
  - `path` (`TEXT`): Path to extension folder
  - `permissions` (`TEXT`): The permissions required by the extension
  - `permissions_json` (`TEXT`, `HIDDEN`): The JSON-encoded permissions required by the extension
  - `optional_permissions` (`TEXT`): The permissions optionally required by the extensions
  - `optional_permissions_json` (`TEXT`, `HIDDEN`): The JSON-encoded permissions optionally required by the extensions
  - `manifest_hash` (`TEXT`): The SHA256 hash of the manifest.json file
  - `referenced` (`BIGINT`): 1 if this extension is referenced by the Preferences file of the profile
  - `from_webstore` (`TEXT`): True if this extension was installed from the web store
  - `state` (`TEXT`): 1 if this extension is enabled
  - `install_time` (`TEXT`): Extension install time, in its original Webkit format
  - `install_timestamp` (`BIGINT`): Extension install time, converted to unix time
  - `manifest_json` (`TEXT`, `HIDDEN`): The manifest file of the extension
  - `key` (`TEXT`, `HIDDEN`): The extension key, from the manifest file

#### `chrome_extension_content_scripts`
- **Source**: `specs/chrome_extension_content_scripts.table`
- **Attributes**: `user_data=True`
- **Description**: Chrome browser extension content scripts.
- **Columns**:
  - `browser_type` (`TEXT`): The browser type (Valid values: chrome, chromium, opera, yandex, brave)
  - `uid` (`BIGINT`, `INDEX`, `OPTIMIZED`): The local user that owns the extension
  - `identifier` (`TEXT`): Extension identifier
  - `version` (`TEXT`): Extension-supplied version
  - `script` (`TEXT`): The content script used by the extension
  - `match` (`TEXT`): The pattern that the script is matched against
  - `profile_path` (`TEXT`): The profile path
  - `path` (`TEXT`): Path to extension folder
  - `referenced` (`BIGINT`): 1 if this extension is referenced by the Preferences file of the profile

#### `firefox_addons`
- **Source**: `specs/firefox_addons.table`
- **Attributes**: `user_data=True`
- **Description**: Firefox browser extensions, webapps, and addons.
- **Columns**:
  - `uid` (`BIGINT`, `ADDITIONAL`, `OPTIMIZED`): The local user that owns the addon
  - `name` (`TEXT`): Addon display name
  - `identifier` (`TEXT`, `INDEX`): Addon identifier
  - `creator` (`TEXT`): Addon-supported creator string
  - `type` (`TEXT`): Extension, addon, webapp
  - `version` (`TEXT`): Addon-supplied version string
  - `description` (`TEXT`): Addon-supplied description string
  - `source_url` (`TEXT`): URL that installed the addon
  - `visible` (`INTEGER`): 1 If the addon is shown in browser else 0
  - `active` (`INTEGER`): 1 If the addon is active else 0
  - `disabled` (`INTEGER`): 1 If the addon is application-disabled else 0
  - `autoupdate` (`INTEGER`): 1 If the addon applies background updates else 0
  - `location` (`TEXT`): Global, profile location
  - `path` (`TEXT`): Path to plugin bundle

#### `vscode_extensions`
- **Source**: `specs/vscode_extensions.table`
- **Attributes**: `user_data=True`
- **Description**: Lists all vscode extensions.
- **Columns**:
  - `name` (`TEXT`): Extension Name
  - `uuid` (`TEXT`): Extension UUID
  - `version` (`TEXT`): Extension version
  - `path` (`TEXT`): Extension path
  - `publisher` (`TEXT`): Publisher Name
  - `publisher_id` (`TEXT`): Publisher ID
  - `installed_at` (`BIGINT`): Installed Timestamp
  - `prerelease` (`INTEGER`): Pre release version
  - `uid` (`BIGINT`, `ADDITIONAL`, `OPTIMIZED`): The local user that owns the plugin
  - `vscode_edition` (`TEXT`): The VSCode edition (vscode, vscode_insiders, vscodium, vscodium_insiders, cursor, windsurf, trae)

#### `jetbrains_plugins`
- **Source**: `specs/jetbrains_plugins.table`
- **Attributes**: `user_data=True`
- **Description**: JetBrains IDEs plugins.
- **Columns**:
  - `product_type` (`TEXT`): The product type (Valid values: CLion, DataGrip, GoLand, IntelliJIdea, IntelliJIdeaCommunityEdition, PhpStorm, PyCharm, PyCharmCommunityEdition, ReSharper, Rider, RubyMine, RustRover, WebStorm)
  - `uid` (`BIGINT`, `INDEX`): The local user that owns the plugin
  - `name` (`TEXT`): Name of the plugin (Title Case)
  - `version` (`TEXT`): Version of the plugin
  - `vendor` (`TEXT`): The vendor name or organization id that authored the plugin
  - `path` (`TEXT`): The path on the filesystem for the plugin. This may be a folder or a jar filename

#### `prometheus_metrics`
- **Source**: `specs/posix/prometheus_metrics.table`
- **Description**: Retrieve metrics from a Prometheus server.
- **Columns**:
  - `target_name` (`TEXT`): Address of prometheus target
  - `metric_name` (`TEXT`): Name of collected Prometheus metric
  - `metric_value` (`DOUBLE`): Value of collected Prometheus metric
  - `timestamp_ms` (`BIGINT`): Unix timestamp of collected data in MS

---

### Category 14: Cloud Instance Metadata & Osquery Internal Utilities (13 Tables)

#### `ec2_instance_metadata`
- **Source**: `specs/ec2_instance_metadata.table`
- **Attributes**: `cacheable=True`
- **Description**: EC2 instance metadata.
- **Columns**:
  - `instance_id` (`TEXT`): EC2 instance ID
  - `instance_type` (`TEXT`): EC2 instance type
  - `architecture` (`TEXT`): Hardware architecture of this EC2 instance
  - `region` (`TEXT`): AWS region in which this instance launched
  - `availability_zone` (`TEXT`): Availability zone in which this instance launched
  - `local_hostname` (`TEXT`): Private IPv4 DNS hostname of the first interface of this instance
  - `local_ipv4` (`TEXT`): Private IPv4 address of the first interface of this instance
  - `mac` (`TEXT`): MAC address for the first network interface of this EC2 instance
  - `security_groups` (`TEXT`): Comma separated list of security group names
  - `iam_arn` (`TEXT`): If there is an IAM role associated with the instance, contains instance profile ARN
  - `ami_id` (`TEXT`): AMI ID used to launch this EC2 instance
  - `reservation_id` (`TEXT`): ID of the reservation
  - `account_id` (`TEXT`): AWS account ID which owns this EC2 instance
  - `ssh_public_key` (`TEXT`): SSH public key. Only available if supplied at instance launch time

#### `ec2_instance_tags`
- **Source**: `specs/ec2_instance_tags.table`
- **Attributes**: `cacheable=True`
- **Description**: EC2 instance tag key value pairs.
- **Columns**:
  - `instance_id` (`TEXT`): EC2 instance ID
  - `key` (`TEXT`): Tag key
  - `value` (`TEXT`): Tag value

#### `azure_instance_metadata`
- **Source**: `specs/azure_instance_metadata.table`
- **Attributes**: `cacheable=True`
- **Description**: Azure instance metadata.
- **Columns**:
  - `location` (`TEXT`): Azure Region the VM is running in
  - `name` (`TEXT`): Name of the VM
  - `offer` (`TEXT`): Offer information for the VM image (Azure image gallery VMs only)
  - `publisher` (`TEXT`): Publisher of the VM image
  - `sku` (`TEXT`): SKU for the VM image
  - `version` (`TEXT`): Version of the VM image
  - `os_type` (`TEXT`): Linux or Windows
  - `platform_update_domain` (`TEXT`): Update domain the VM is running in
  - `platform_fault_domain` (`TEXT`): Fault domain the VM is running in
  - `vm_id` (`TEXT`, `INDEX`): Unique identifier for the VM
  - `vm_size` (`TEXT`): VM size
  - `subscription_id` (`TEXT`): Azure subscription for the VM
  - `resource_group_name` (`TEXT`): Resource group for the VM
  - `placement_group_id` (`TEXT`): Placement group for the VM scale set
  - `vm_scale_set_name` (`TEXT`): VM scale set name
  - `zone` (`TEXT`): Availability zone of the VM

#### `azure_instance_tags`
- **Source**: `specs/azure_instance_tags.table`
- **Attributes**: `cacheable=True`
- **Description**: Azure instance tags.
- **Columns**:
  - `vm_id` (`TEXT`): Unique identifier for the VM
  - `key` (`TEXT`): The tag key
  - `value` (`TEXT`): The tag value

#### `ycloud_instance_metadata`
- **Source**: `specs/ycloud_instance_metadata.table`
- **Attributes**: `cacheable=True`
- **Description**: Yandex.Cloud instance metadata.
- **Columns**:
  - `instance_id` (`TEXT`, `INDEX`): Unique identifier for the VM
  - `folder_id` (`TEXT`): Folder identifier for the VM
  - `cloud_id` (`TEXT`): Cloud identifier for the VM
  - `name` (`TEXT`): Name of the VM
  - `description` (`TEXT`): Description of the VM
  - `hostname` (`TEXT`): Hostname of the VM
  - `zone` (`TEXT`): Availability zone of the VM
  - `ssh_public_key` (`TEXT`): SSH public key. Only available if supplied at instance launch time
  - `serial_port_enabled` (`TEXT`): Indicates if serial port is enabled for the VM
  - `metadata_endpoint` (`TEXT`, `INDEX`): Endpoint used to fetch VM metadata

#### `time`
- **Source**: `specs/utility/time.table`
- **Attributes**: `utility=True`
- **Description**: Track current date and time in UTC.
- **Columns**:
  - `weekday` (`TEXT`): Current weekday in UTC
  - `year` (`INTEGER`): Current year in UTC
  - `month` (`INTEGER`): Current month in UTC
  - `day` (`INTEGER`): Current day in UTC
  - `hour` (`INTEGER`): Current hour in UTC
  - `minutes` (`INTEGER`): Current minutes in UTC
  - `seconds` (`INTEGER`): Current seconds in UTC
  - `timezone` (`TEXT`): Timezone for reported time (hardcoded to UTC)
  - `local_timezone` (`TEXT`): Current local timezone in of the system
  - `unix_time` (`INTEGER`): Current UNIX time in UTC
  - `timestamp` (`TEXT`): Current timestamp (log format) in UTC
  - `datetime` (`TEXT`, alias: `date_time`): Current date and time (ISO format) in UTC
  - `iso_8601` (`TEXT`): Current time (ISO format) in UTC

#### `osquery_info`
- **Source**: `specs/utility/osquery_info.table`
- **Attributes**: `utility=True`
- **Description**: Top level information about the running version of osquery.
- **Columns**:
  - `pid` (`INTEGER`): Process (or thread/handle) ID
  - `uuid` (`TEXT`): Unique ID provided by the system
  - `instance_id` (`TEXT`): Unique, long-lived ID per instance of osquery
  - `version` (`TEXT`): osquery toolkit version
  - `config_hash` (`TEXT`): Hash of the working configuration state
  - `config_valid` (`INTEGER`): 1 if the config was loaded and considered valid, else 0
  - `extensions` (`TEXT`): osquery extensions status
  - `build_platform` (`TEXT`): osquery toolkit build platform
  - `build_distro` (`TEXT`): osquery toolkit platform distribution name (os version)
  - `start_time` (`INTEGER`): UNIX time in seconds when the process started
  - `watcher` (`INTEGER`): Process (or thread/handle) ID of optional watcher process
  - `platform_mask` (`INTEGER`): The osquery platform bitmask

#### `osquery_flags`
- **Source**: `specs/utility/osquery_flags.table`
- **Attributes**: `utility=True`
- **Description**: Configurable flags that modify osquery's behavior.
- **Columns**:
  - `name` (`TEXT`): Flag name
  - `type` (`TEXT`): Flag type
  - `description` (`TEXT`): Flag description
  - `default_value` (`TEXT`): Flag default value
  - `value` (`TEXT`): Flag value
  - `shell_only` (`INTEGER`): Is the flag shell only?

#### `osquery_events`
- **Source**: `specs/utility/osquery_events.table`
- **Attributes**: `utility=True`
- **Description**: Information about the event publishers and subscribers.
- **Columns**:
  - `name` (`TEXT`): Event publisher or subscriber name
  - `publisher` (`TEXT`): Name of the associated publisher
  - `type` (`TEXT`): Either publisher or subscriber
  - `subscriptions` (`INTEGER`): Number of subscriptions the publisher received or subscriber used
  - `events` (`INTEGER`): Number of events emitted or received since osquery started
  - `refreshes` (`INTEGER`): Publisher only: number of runloop restarts
  - `active` (`INTEGER`): 1 if the publisher or subscriber is active else 0

#### `osquery_extensions`
- **Source**: `specs/utility/osquery_extensions.table`
- **Attributes**: `utility=True`
- **Description**: List of active osquery extensions.
- **Columns**:
  - `uuid` (`BIGINT`): The transient ID assigned for communication
  - `name` (`TEXT`): Extension's name
  - `version` (`TEXT`): Extension's version
  - `sdk_version` (`TEXT`): osquery SDK version used to build the extension
  - `path` (`TEXT`): Path of the extension's Thrift connection or library path
  - `type` (`TEXT`): SDK extension type: core, extension, or module

#### `osquery_packs`
- **Source**: `specs/utility/osquery_packs.table`
- **Attributes**: `utility=True`
- **Description**: Information about the current query packs that are loaded in osquery.
- **Columns**:
  - `name` (`TEXT`): The given name for this query pack
  - `platform` (`TEXT`): Platforms this query is supported on
  - `version` (`TEXT`): Minimum osquery version that this query will run on
  - `shard` (`INTEGER`): Shard restriction limit, 1-100, 0 meaning no restriction
  - `discovery_cache_hits` (`INTEGER`): The number of times that the discovery query used cached values since the last time the config was reloaded
  - `discovery_executions` (`INTEGER`): The number of times that the discovery queries have been executed since the last time the config was reloaded
  - `active` (`INTEGER`): Whether this pack is active (the version, platform and discovery queries match) yes=1, no=0.

#### `osquery_registry`
- **Source**: `specs/utility/osquery_registry.table`
- **Attributes**: `utility=True`
- **Description**: List the osquery registry plugins.
- **Columns**:
  - `registry` (`TEXT`): Name of the osquery registry
  - `name` (`TEXT`): Name of the plugin item
  - `owner_uuid` (`INTEGER`): Extension route UUID (0 for core)
  - `internal` (`INTEGER`): 1 If the plugin is internal else 0
  - `active` (`INTEGER`): 1 If this plugin is active else 0

#### `osquery_schedule`
- **Source**: `specs/utility/osquery_schedule.table`
- **Attributes**: `utility=True`
- **Description**: Information about the current queries that are scheduled in osquery.
- **Columns**:
  - `name` (`TEXT`): The given name for this query
  - `query` (`TEXT`): The exact query to run
  - `interval` (`INTEGER`): The interval in seconds to run this query, not an exact interval
  - `executions` (`BIGINT`): Number of times the query was executed
  - `last_executed` (`BIGINT`): UNIX time stamp in seconds of the last completed execution
  - `denylisted` (`INTEGER`, alias: `blacklisted`): 1 if the query is denylisted else 0
  - `output_size` (`BIGINT`): Cumulative total number of bytes generated by the resultant rows of the query
  - `wall_time` (`BIGINT`, `HIDDEN`): Total wall time in seconds spent executing (deprecated)
  - `wall_time_ms` (`BIGINT`): Total wall time in milliseconds spent executing
  - `last_wall_time_ms` (`BIGINT`): Wall time in milliseconds of the latest execution
  - `user_time` (`BIGINT`): Total user time in milliseconds spent executing
  - `last_user_time` (`BIGINT`): User time in milliseconds of the latest execution
  - `system_time` (`BIGINT`): Total system time in milliseconds spent executing
  - `last_system_time` (`BIGINT`): System time in milliseconds of the latest execution
  - `average_memory` (`BIGINT`): Average of the bytes of resident memory left allocated after collecting results
  - `last_memory` (`BIGINT`): Resident memory in bytes left allocated after collecting results of the latest execution
