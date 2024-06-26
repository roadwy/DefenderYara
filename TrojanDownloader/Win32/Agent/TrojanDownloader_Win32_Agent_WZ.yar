
rule TrojanDownloader_Win32_Agent_WZ{
	meta:
		description = "TrojanDownloader:Win32/Agent.WZ,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 11 00 00 01 00 "
		
	strings :
		$a_00_0 = {4f 52 49 47 41 4d 49 } //01 00  ORIGAMI
		$a_00_1 = {3f 73 65 6c 66 3d } //01 00  ?self=
		$a_00_2 = {26 74 79 70 65 3d } //01 00  &type=
		$a_00_3 = {26 6b 65 79 3d } //01 00  &key=
		$a_00_4 = {61 6c 69 76 65 } //01 00  alive
		$a_00_5 = {72 75 6e 6e 65 64 } //0a 00  runned
		$a_00_6 = {54 4e 44 31 68 74 74 70 3a 2f 2f 38 35 2e 32 35 35 2e 31 31 39 } //0a 00  TND1http://85.255.119
		$a_00_7 = {54 4e 44 32 } //02 00  TND2
		$a_00_8 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e 5c 4e 6f 74 69 66 79 5c 6f 72 69 67 61 6d 69 } //02 00  SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\origami
		$a_00_9 = {42 00 43 00 42 00 43 00 40 00 41 00 } //01 00  BCBC@A
		$a_00_10 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_00_11 = {77 69 6e 69 6e 65 74 2e 64 6c 6c } //01 00  wininet.dll
		$a_01_12 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_01_13 = {49 6e 74 65 72 6e 65 74 47 65 74 43 6f 6e 6e 65 63 74 65 64 53 74 61 74 65 } //01 00  InternetGetConnectedState
		$a_01_14 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_15 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //01 00  CreateRemoteThread
		$a_00_16 = {57 72 69 74 65 46 69 6c 65 } //00 00  WriteFile
	condition:
		any of ($a_*)
 
}