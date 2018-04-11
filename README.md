# latebros
x64 usermode rootkit. This was a project i made (with help from Daax and JustMagic) while researching usermode rootkits. Project is neither under development nor finished.

# Capabilities
- Hide process from enumeration
- Hide registry key from enumeration
- Hide file for modification
- Protect process from modification
- Protect file from modification
- Protect registry key from erasure


# Hooks
- ntdll.dll!NtOpenProcess
- ntdll.dll!NtQuerySystemInformation
- ntdll.dll!NtCreateFile
- ntdll.dll!NtOpenFile
- ntdll.dll!NtQueryDirectoryFile
- ntdll.dll!NtDeleteValueKey
- ntdll.dll!NtEnumerateValueKey

# Thanks to
- Daax
- JustMagic
