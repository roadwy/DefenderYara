
rule Trojan_Win32_Agent_AAC{
	meta:
		description = "Trojan:Win32/Agent.AAC,SIGNATURE_TYPE_PEHSTR_EXT,11 00 10 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {47 6f 74 6f 20 53 75 70 65 72 72 53 6f 66 74 2e 63 6f 6d 2e 55 52 4c } //01 00  Goto SuperrSoft.com.URL
		$a_00_1 = {33 36 30 73 61 66 65 } //01 00  360safe
		$a_00_2 = {77 6f 70 74 69 63 6c 65 61 6e } //01 00  wopticlean
		$a_00_3 = {71 71 2e 65 78 65 } //01 00  qq.exe
		$a_00_4 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //01 00  rundll32.exe
		$a_00_5 = {74 61 73 6b 6d 67 72 2e 65 78 65 } //01 00  taskmgr.exe
		$a_01_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_7 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //00 00  SeShutdownPrivilege
	condition:
		any of ($a_*)
 
}