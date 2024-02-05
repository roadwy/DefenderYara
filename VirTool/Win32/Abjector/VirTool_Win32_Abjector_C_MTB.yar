
rule VirTool_Win32_Abjector_C_MTB{
	meta:
		description = "VirTool:Win32/Abjector.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 51 51 8d 85 90 01 04 90 02 07 50 51 90 02 03 c7 85 90 1b 00 01 00 00 00 ff 15 90 02 29 6a 00 b8 00 00 10 00 8d 0c 37 2b c7 50 51 90 02 03 ff 15 90 00 } //01 00 
		$a_02_1 = {80 3c 37 20 74 90 01 01 56 47 ff 90 02 05 3b f8 7c 90 02 1b 20 90 02 02 e8 90 02 06 83 f8 01 7e 08 8d 46 01 03 c7 89 45 90 01 01 c6 04 37 00 90 00 } //01 00 
		$a_02_2 = {50 6a 08 ff 15 90 01 04 50 ff 15 90 01 04 85 c0 90 02 07 8d 45 90 01 01 89 75 90 01 01 50 6a 04 8d 45 e8 50 90 02 02 6a 90 01 01 ff 75 fc ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}