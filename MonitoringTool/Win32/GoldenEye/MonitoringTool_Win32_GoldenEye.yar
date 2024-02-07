
rule MonitoringTool_Win32_GoldenEye{
	meta:
		description = "MonitoringTool:Win32/GoldenEye,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 45 48 50 2e 64 6c 6c 00 49 6e 69 74 00 53 65 74 56 69 73 69 62 6c 65 } //01 00  䕇偈搮汬䤀楮t敓噴獩扩敬
		$a_01_1 = {6d 43 48 53 57 44 49 4d 75 74 65 78 00 } //01 00 
		$a_01_2 = {4e 74 43 72 65 61 74 65 50 72 6f 63 65 73 73 45 78 } //01 00  NtCreateProcessEx
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //01 00  SetWindowsHookExA
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //00 00  SOFTWARE\Borland\Delphi
	condition:
		any of ($a_*)
 
}