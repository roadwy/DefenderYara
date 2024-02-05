
rule VirTool_Win32_Avet_14_MTB{
	meta:
		description = "VirTool:Win32/Avet.14!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {c7 44 24 30 00 00 00 00 8b 45 0c 83 c0 10 8b 00 8d 54 90 01 02 89 54 24 04 89 04 24 8b 84 24 84 28 00 00 ff 90 00 } //01 00 
		$a_00_1 = {81 e9 00 10 00 00 83 09 00 2d 00 10 00 00 3d 00 10 00 00 77 } //01 00 
		$a_02_2 = {8b 84 24 98 28 00 00 8b 84 84 34 28 00 00 8d 90 01 03 8b 94 24 98 28 00 00 c1 e2 0a 01 ca 89 14 24 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}