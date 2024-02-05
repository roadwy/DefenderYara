
rule VirTool_Win32_Tinmet_A{
	meta:
		description = "VirTool:Win32/Tinmet.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {56 89 75 fc ff d3 a1 90 01 04 6a 40 68 00 10 00 00 83 c0 05 50 90 02 06 ff 15 90 00 } //02 00 
		$a_03_1 = {c7 45 fc 80 33 00 00 50 6a 1f 56 ff 15 90 01 04 53 53 53 53 56 ff 15 90 01 04 85 c0 75 07 68 90 01 04 eb 90 01 01 6a 40 68 00 10 00 00 68 00 00 40 00 53 ff 15 90 00 } //01 00 
		$a_03_2 = {83 c4 0c a3 90 01 03 00 ff d0 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 } //d7 26 
	condition:
		any of ($a_*)
 
}