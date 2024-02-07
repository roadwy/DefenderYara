
rule Trojan_Win32_Spynoon_AVM_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.AVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 79 76 6b 66 63 6f 72 66 } //01 00  Hyvkfcorf
		$a_01_1 = {53 00 48 00 4c 00 57 00 41 00 50 00 49 00 2e 00 44 00 4c 00 4c 00 } //01 00  SHLWAPI.DLL
		$a_81_2 = {31 34 31 3a 31 40 31 46 31 4c 31 52 31 58 31 } //01 00  141:1@1F1L1R1X1
		$a_81_3 = {31 64 31 6a 31 70 31 76 31 7c 31 } //00 00  1d1j1p1v1|1
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Spynoon_AVM_MTB_2{
	meta:
		description = "Trojan:Win32/Spynoon.AVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 72 65 61 74 65 46 69 6c 65 57 } //01 00  CreateFileW
		$a_81_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  IsDebuggerPresent
		$a_81_2 = {44 65 62 75 67 42 72 65 61 6b } //01 00  DebugBreak
		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_81_4 = {48 79 76 6b 66 63 6f 72 66 } //00 00  Hyvkfcorf
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Spynoon_AVM_MTB_3{
	meta:
		description = "Trojan:Win32/Spynoon.AVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 66 6b 63 64 6f 65 6b 78 6c 7a 4f 6a 62 74 } //01 00  HfkcdoekxlzOjbt
		$a_81_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_81_2 = {52 70 63 4d 67 6d 74 49 6e 71 43 6f 6d 54 69 6d 65 6f 75 74 } //01 00  RpcMgmtInqComTimeout
		$a_81_3 = {52 70 63 4d 67 6d 74 53 65 74 43 61 6e 63 65 6c 54 69 6d 65 6f 75 74 } //01 00  RpcMgmtSetCancelTimeout
		$a_81_4 = {4e 64 72 43 6f 6e 66 6f 72 6d 61 6e 74 53 74 72 75 63 74 55 6e 6d 61 72 73 68 61 6c 6c } //01 00  NdrConformantStructUnmarshall
		$a_81_5 = {52 70 63 53 6d 53 65 74 43 6c 69 65 6e 74 41 6c 6c 6f 63 46 72 65 65 } //01 00  RpcSmSetClientAllocFree
		$a_81_6 = {4e 64 72 42 79 74 65 43 6f 75 6e 74 50 6f 69 6e 74 65 72 46 72 65 65 } //01 00  NdrByteCountPointerFree
		$a_81_7 = {4e 64 72 46 75 6c 6c 50 6f 69 6e 74 65 72 58 6c 61 74 46 72 65 65 } //00 00  NdrFullPointerXlatFree
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Spynoon_AVM_MTB_4{
	meta:
		description = "Trojan:Win32/Spynoon.AVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 68 65 6c 6c 5f 4e 6f 74 69 66 79 49 63 6f 6e } //01 00  Shell_NotifyIcon
		$a_81_1 = {45 78 74 72 61 63 74 41 73 73 6f 63 69 61 74 65 64 49 63 6f 6e 45 78 57 } //01 00  ExtractAssociatedIconExW
		$a_81_2 = {43 75 72 73 6f 72 4c 69 62 4c 6f 63 6b 53 74 6d 74 } //01 00  CursorLibLockStmt
		$a_81_3 = {43 72 65 61 74 65 41 6e 74 69 4d 6f 6e 69 6b 65 72 } //01 00  CreateAntiMoniker
		$a_81_4 = {53 74 67 4f 70 65 6e 53 74 6f 72 61 67 65 4f 6e 49 4c 6f 63 6b 42 79 74 65 73 } //01 00  StgOpenStorageOnILockBytes
		$a_81_5 = {48 4d 45 54 41 46 49 4c 45 50 49 43 54 5f 55 73 65 72 4d 61 72 73 68 61 6c } //01 00  HMETAFILEPICT_UserMarshal
		$a_81_6 = {53 74 67 49 73 53 74 6f 72 61 67 65 49 4c 6f 63 6b 42 79 74 65 73 } //01 00  StgIsStorageILockBytes
		$a_81_7 = {52 65 67 69 73 74 65 72 44 72 61 67 44 72 6f 70 } //01 00  RegisterDragDrop
		$a_81_8 = {72 65 78 65 63 } //01 00  rexec
		$a_81_9 = {4e 50 4c 6f 61 64 4e 61 6d 65 53 70 61 63 65 73 } //01 00  NPLoadNameSpaces
		$a_81_10 = {72 72 65 73 76 70 6f 72 74 } //01 00  rresvport
		$a_00_11 = {52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 4d 00 70 00 44 00 72 00 69 00 76 00 65 00 72 00 } //00 00  Registry\Machine\System\CurrentControlSet\Services\MpDriver
	condition:
		any of ($a_*)
 
}