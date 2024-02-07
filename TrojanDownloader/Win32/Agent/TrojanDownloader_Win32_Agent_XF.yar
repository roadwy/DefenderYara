
rule TrojanDownloader_Win32_Agent_XF{
	meta:
		description = "TrojanDownloader:Win32/Agent.XF,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 76 63 68 6f 73 74 2e 65 78 65 } //01 00  svchost.exe
		$a_00_1 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //01 00  ResumeThread
		$a_00_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //01 00  VirtualProtectEx
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //03 00  WriteProcessMemory
		$a_02_4 = {e8 ff ff ff ff c0 5d 89 eb 31 c9 81 e9 77 fe ff ff 83 eb e2 81 73 fb 90 01 04 43 e2 f6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}