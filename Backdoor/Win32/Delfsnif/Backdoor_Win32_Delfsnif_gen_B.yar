
rule Backdoor_Win32_Delfsnif_gen_B{
	meta:
		description = "Backdoor:Win32/Delfsnif.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,36 01 31 01 1a 00 00 64 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 43 3c 03 c3 83 c0 04 83 c0 14 8b 70 60 03 f3 8b 6e 18 4d 85 ed 72 41 45 33 ff 8b 46 20 03 c3 8b d7 c1 e2 02 03 c2 8b 00 03 c3 8b 14 24 e8 90 01 04 85 c0 75 1e 8b 46 24 03 c3 8b d7 03 d2 03 c2 0f b7 00 c1 e0 02 8b 56 1c 03 d3 03 c2 8b 00 03 c3 eb 06 47 4d 75 c2 90 00 } //64 00 
		$a_00_1 = {25 73 5c 6e 65 74 73 68 2e 65 78 65 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //0a 00  %s\netsh.exe firewall add allowedprogram
		$a_00_2 = {4c 63 53 68 69 65 6c 64 } //0a 00  LcShield
		$a_00_3 = {76 69 6e 76 6e 63 34 } //0a 00  vinvnc4
		$a_00_4 = {53 66 6d 61 6e 74 65 63 20 41 6e 74 69 70 69 72 75 73 } //0a 00  Sfmantec Antipirus
		$a_00_5 = {52 61 76 5f 6f 6e 43 6c 61 73 73 } //0a 00  Rav_onClass
		$a_00_6 = {54 66 4c 6f 63 6b 44 6f 77 6e 4d 61 69 6e } //0a 00  TfLockDownMain
		$a_00_7 = {5a 41 47 72 61 6d 65 57 6e 64 } //0a 00  ZAGrameWnd
		$a_00_8 = {54 4d 61 6c 77 61 72 65 49 74 65 6d } //0a 00  TMalwareItem
		$a_00_9 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 } //0a 00  http://%s:%d/%s
		$a_00_10 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //0a 00  \drivers\etc\hosts
		$a_00_11 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e } //01 00  software\microsoft\windows\currentversion
		$a_00_12 = {47 65 74 4e 65 74 77 6f 72 6b 50 61 72 61 6d 73 } //01 00  GetNetworkParams
		$a_00_13 = {49 63 6d 70 53 65 6e 64 45 63 68 6f } //01 00  IcmpSendEcho
		$a_00_14 = {57 53 41 52 65 63 76 } //01 00  WSARecv
		$a_00_15 = {57 53 41 53 65 6e 64 } //01 00  WSASend
		$a_00_16 = {57 53 41 43 6f 6e 6e 65 63 74 } //01 00  WSAConnect
		$a_00_17 = {4e 74 43 72 65 61 74 65 46 69 6c 65 } //01 00  NtCreateFile
		$a_00_18 = {44 45 56 49 43 45 5c 54 43 50 } //01 00  DEVICE\TCP
		$a_00_19 = {4e 74 50 72 6f 74 65 63 74 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //01 00  NtProtectVirtualMemory
		$a_00_20 = {4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //01 00  NtWriteVirtualMemory
		$a_01_21 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_00_22 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //01 00  OpenProcess
		$a_00_23 = {4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e } //01 00  OpenProcessToken
		$a_00_24 = {4c 6f 6f 6b 75 70 50 72 69 76 69 6c 65 67 65 56 61 6c 75 65 41 } //01 00  LookupPrivilegeValueA
		$a_00_25 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //00 00  AdjustTokenPrivileges
	condition:
		any of ($a_*)
 
}