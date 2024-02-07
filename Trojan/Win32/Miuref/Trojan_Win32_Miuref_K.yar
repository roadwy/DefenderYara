
rule Trojan_Win32_Miuref_K{
	meta:
		description = "Trojan:Win32/Miuref.K,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 65 72 5f 75 2e 64 6c 6c } //01 00  loader_u.dll
		$a_01_1 = {6b d2 1f 03 d1 83 c0 02 } //01 00 
		$a_01_2 = {3d 75 c0 8e 88 } //01 00 
		$a_01_3 = {3d a5 d3 d5 4b } //01 00 
		$a_00_4 = {3d ee 86 47 cf } //00 00 
		$a_00_5 = {87 10 00 } //00 cb 
	condition:
		any of ($a_*)
 
}