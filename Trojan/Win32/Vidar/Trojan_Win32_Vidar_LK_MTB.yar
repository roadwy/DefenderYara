
rule Trojan_Win32_Vidar_LK_MTB{
	meta:
		description = "Trojan:Win32/Vidar.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {81 ea 4e 44 27 29 0f be 45 fe 2b c2 88 45 fe 8b 4d dc 83 c1 01 89 4d dc 81 7d dc 94 14 00 00 7c d8 } //4
		$a_81_1 = {48 74 74 70 41 6e 61 6c 79 7a 65 72 53 74 64 56 37 2e 65 78 65 } //1 HttpAnalyzerStdV7.exe
		$a_81_2 = {48 54 54 50 44 65 62 75 67 67 65 72 55 49 2e 65 78 65 } //1 HTTPDebuggerUI.exe
		$a_81_3 = {57 69 72 65 73 68 61 72 6b 2e 65 78 65 } //1 Wireshark.exe
		$a_81_4 = {50 52 4f 43 45 58 50 36 34 2e 65 78 65 } //1 PROCEXP64.exe
	condition:
		((#a_01_0  & 1)*4+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}