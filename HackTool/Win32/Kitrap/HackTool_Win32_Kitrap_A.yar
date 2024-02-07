
rule HackTool_Win32_Kitrap_A{
	meta:
		description = "HackTool:Win32/Kitrap.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 a1 1c 00 00 00 5a 89 50 04 8b 88 24 01 00 00 } //01 00 
		$a_01_1 = {64 a1 1c 00 00 00 8b 7d 58 8b 3f 8b 70 04 b9 84 } //01 00 
		$a_01_2 = {a1 1c f0 df ff 8b 7d 58 8b 3f 8b 88 24 01 00 00 } //01 00 
		$a_01_3 = {64 a1 1c 00 00 00 8b 7d 58 8b 3f 8b 88 24 01 00 } //01 00 
		$a_01_4 = {4e 74 56 64 6d 43 6f 6e 74 72 6f 6c } //01 00  NtVdmControl
		$a_00_5 = {56 44 4d 45 58 50 4c 4f 49 54 2e 44 4c 4c } //00 00  VDMEXPLOIT.DLL
	condition:
		any of ($a_*)
 
}