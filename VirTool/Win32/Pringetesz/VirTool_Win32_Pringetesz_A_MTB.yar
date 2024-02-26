
rule VirTool_Win32_Pringetesz_A_MTB{
	meta:
		description = "VirTool:Win32/Pringetesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 30 33 40 00 90 01 05 8b 35 04 30 40 00 83 c4 04 68 54 33 40 00 53 90 01 02 68 64 33 40 00 53 90 01 02 68 74 33 40 00 53 8b f8 90 01 02 68 8c 33 40 00 53 89 44 24 1c 90 00 } //01 00 
		$a_03_1 = {83 c4 04 ff 74 24 10 68 fc 33 40 00 90 01 05 83 c4 08 90 01 04 50 90 01 04 50 68 ff ff 1f 00 90 01 04 50 90 01 02 a3 74 53 40 00 85 c0 90 00 } //01 00 
		$a_03_2 = {ff 74 24 28 68 c0 34 40 00 90 01 05 83 c4 08 90 01 04 6a 00 68 cd 01 00 00 50 ff 74 24 34 ff 74 24 34 90 01 04 a3 74 53 40 00 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}