
rule VirTool_Win32_Temeresz_A_MTB{
	meta:
		description = "VirTool:Win32/Temeresz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 fc 53 56 57 68 3c 32 40 00 e8 90 01 04 68 5c 32 40 00 e8 90 01 04 83 c4 08 6a 00 6a 00 68 10 11 40 00 6a 0d ff 15 90 00 } //01 00 
		$a_03_1 = {81 3d 80 43 40 00 a2 00 00 00 57 90 01 02 81 fe a5 00 00 00 90 01 02 68 84 31 40 00 e8 90 01 04 83 c4 04 c7 45 0c 00 00 00 00 6a 10 ff 15 90 01 04 0f b7 f8 8d 90 01 02 c1 ef 0f 83 e7 90 00 } //01 00 
		$a_03_2 = {85 ff 74 2d ff 15 90 01 04 85 c0 90 01 02 8d 90 01 02 51 50 ff 15 90 01 04 33 c0 39 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}