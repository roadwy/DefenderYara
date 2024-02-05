
rule Trojan_Win32_Patched_AF{
	meta:
		description = "Trojan:Win32/Patched.AF,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 68 65 6c 6c 33 32 } //01 00 
		$a_00_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //05 00 
		$a_02_2 = {5a 52 52 bb 90 01 04 ff d3 5b 53 83 c3 0c 53 50 b9 90 01 04 ff d1 5a 6a 01 6a 00 6a 00 8b ca 83 c1 1a 51 6a 00 6a 00 ff d0 b8 90 01 04 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}