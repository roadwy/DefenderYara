
rule Trojan_Win32_Rootkit_AF{
	meta:
		description = "Trojan:Win32/Rootkit.AF,SIGNATURE_TYPE_PEHSTR_EXT,ffffffe5 0b fffffff3 07 37 00 00 ffffffe8 03 "
		
	strings :
		$a_02_0 = {01 00 6a 00 6a 00 6a 00 6a 00 8d 85 a0 fd ff ff 50 ff 15 90 01 02 01 00 89 85 94 fd ff ff 90 00 } //e8 03 
		$a_02_1 = {8d 85 34 ff ff ff 50 6a 01 6a 00 68 00 90 01 01 00 00 8d 85 8c fd ff ff 50 6a 00 ff 75 08 ff 15 90 01 02 01 00 89 85 94 fd ff ff 90 00 } //e8 03 
		$a_02_2 = {83 bd 34 ff ff ff 00 74 90 01 01 ff b5 34 ff ff ff ff 15 90 01 02 01 00 90 00 } //e8 03 
		$a_02_3 = {50 68 3f 00 0f 00 8d 45 f4 50 ff 15 90 01 02 01 00 89 45 e4 90 00 } //e8 03 
		$a_02_4 = {8d 45 e8 50 ff 75 fc ff 75 f8 6a 01 8d 45 ec 50 ff 75 f4 ff 15 90 01 02 01 00 89 45 e4 90 00 } //01 00 
		$a_01_5 = {5a 77 43 72 65 61 74 65 46 69 6c 65 } //01 00  ZwCreateFile
		$a_01_6 = {50 73 43 72 65 61 74 65 53 79 73 74 65 6d 54 68 72 65 61 64 } //01 00  PsCreateSystemThread
		$a_01_7 = {4b 65 49 6e 73 65 72 74 51 75 65 75 65 41 70 63 } //01 00  KeInsertQueueApc
		$a_01_8 = {49 6f 44 65 6c 65 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b } //01 00  IoDeleteSymbolicLink
		$a_01_9 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 57 } //01 00  GetSystemDirectoryW
		$a_01_10 = {5a 77 4f 70 65 6e 4b 65 79 } //01 00  ZwOpenKey
		$a_01_11 = {49 6f 41 6c 6c 6f 63 61 74 65 4d 64 6c } //01 00  IoAllocateMdl
		$a_01_12 = {49 6f 43 72 65 61 74 65 44 65 76 69 63 65 } //01 00  IoCreateDevice
		$a_01_13 = {73 74 72 6e 63 6d 70 } //01 00  strncmp
		$a_01_14 = {5a 77 51 75 65 72 79 49 6e 66 6f 72 6d 61 74 69 6f 6e 46 69 6c 65 } //01 00  ZwQueryInformationFile
		$a_01_15 = {4b 65 53 74 61 63 6b 41 74 74 61 63 68 50 72 6f 63 65 73 73 } //01 00  KeStackAttachProcess
		$a_01_16 = {4b 65 53 65 74 45 76 65 6e 74 } //01 00  KeSetEvent
		$a_01_17 = {5a 77 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //01 00  ZwAllocateVirtualMemory
		$a_01_18 = {6e 74 6f 73 6b 72 6e 6c 2e 65 78 65 } //01 00  ntoskrnl.exe
		$a_01_19 = {5a 77 4d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  ZwMapViewOfSection
		$a_01_20 = {5a 77 43 6c 6f 73 65 } //01 00  ZwClose
		$a_01_21 = {4b 65 55 6e 73 74 61 63 6b 44 65 74 61 63 68 50 72 6f 63 65 73 73 } //01 00  KeUnstackDetachProcess
		$a_01_22 = {5a 77 43 72 65 61 74 65 53 65 63 74 69 6f 6e } //01 00  ZwCreateSection
		$a_01_23 = {4b 65 49 6e 69 74 69 61 6c 69 7a 65 41 70 63 } //01 00  KeInitializeApc
		$a_01_24 = {44 65 6c 65 74 65 46 69 6c 65 57 } //01 00  DeleteFileW
		$a_01_25 = {77 63 73 63 70 79 } //01 00  wcscpy
		$a_00_26 = {49 00 6d 00 61 00 67 00 65 00 50 00 61 00 74 00 68 00 } //01 00  ImagePath
		$a_01_27 = {4c 6f 61 64 4c 69 62 72 61 72 79 57 } //01 00  LoadLibraryW
		$a_01_28 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  ZwUnmapViewOfSection
		$a_01_29 = {4d 6d 47 65 74 53 79 73 74 65 6d 52 6f 75 74 69 6e 65 41 64 64 72 65 73 73 } //01 00  MmGetSystemRoutineAddress
		$a_01_30 = {50 73 47 65 74 56 65 72 73 69 6f 6e } //01 00  PsGetVersion
		$a_01_31 = {49 6f 44 65 6c 65 74 65 44 65 76 69 63 65 } //01 00  IoDeleteDevice
		$a_01_32 = {49 6f 46 72 65 65 4d 64 6c } //01 00  IoFreeMdl
		$a_01_33 = {45 78 41 6c 6c 6f 63 61 74 65 50 6f 6f 6c 57 69 74 68 54 61 67 } //01 00  ExAllocatePoolWithTag
		$a_01_34 = {5a 77 51 75 65 72 79 56 61 6c 75 65 4b 65 79 } //01 00  ZwQueryValueKey
		$a_01_35 = {4b 65 49 6e 69 74 69 61 6c 69 7a 65 45 76 65 6e 74 } //01 00  KeInitializeEvent
		$a_01_36 = {4d 6d 55 6e 6c 6f 63 6b 50 61 67 65 73 } //01 00  MmUnlockPages
		$a_01_37 = {5a 77 4f 70 65 6e 46 69 6c 65 } //01 00  ZwOpenFile
		$a_01_38 = {4d 6d 50 72 6f 62 65 41 6e 64 4c 6f 63 6b 50 61 67 65 73 } //01 00  MmProbeAndLockPages
		$a_01_39 = {5a 77 57 72 69 74 65 46 69 6c 65 } //01 00  ZwWriteFile
		$a_01_40 = {49 6f 66 43 6f 6d 70 6c 65 74 65 52 65 71 75 65 73 74 } //01 00  IofCompleteRequest
		$a_01_41 = {49 6f 47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //01 00  IoGetCurrentProcess
		$a_01_42 = {49 6f 43 72 65 61 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b } //01 00  IoCreateSymbolicLink
		$a_01_43 = {6c 73 74 72 63 61 74 57 } //01 00  lstrcatW
		$a_01_44 = {5a 77 52 65 61 64 46 69 6c 65 } //01 00  ZwReadFile
		$a_01_45 = {4d 6d 4d 61 70 4c 6f 63 6b 65 64 50 61 67 65 73 53 70 65 63 69 66 79 43 61 63 68 65 } //01 00  MmMapLockedPagesSpecifyCache
		$a_01_46 = {5f 73 74 72 69 63 6d 70 } //01 00  _stricmp
		$a_01_47 = {4b 65 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //01 00  KeWaitForSingleObject
		$a_01_48 = {5f 65 78 63 65 70 74 5f 68 61 6e 64 6c 65 72 33 } //01 00  _except_handler3
		$a_01_49 = {52 74 6c 49 6e 69 74 55 6e 69 63 6f 64 65 53 74 72 69 6e 67 } //01 00  RtlInitUnicodeString
		$a_01_50 = {5a 77 4f 70 65 6e 50 72 6f 63 65 73 73 } //01 00  ZwOpenProcess
		$a_01_51 = {50 73 54 65 72 6d 69 6e 61 74 65 53 79 73 74 65 6d 54 68 72 65 61 64 } //01 00  PsTerminateSystemThread
		$a_01_52 = {77 63 73 63 61 74 } //01 00  wcscat
		$a_01_53 = {68 2e 72 64 61 74 61 } //01 00  h.rdata
		$a_01_54 = {48 2e 64 61 74 61 } //00 00  H.data
	condition:
		any of ($a_*)
 
}