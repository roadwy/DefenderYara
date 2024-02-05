
rule VirTool_Win32_Abjector_A_MTB{
	meta:
		description = "VirTool:Win32/Abjector.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {cc 55 8b ec 90 02 08 64 90 02 02 30 00 00 00 90 02 0e 8b 90 01 01 0c 83 90 01 01 0c 90 00 } //01 00 
		$a_00_1 = {c1 c0 07 8d 52 01 0f be c9 33 c1 8a 0a 84 c9 } //01 00 
		$a_02_2 = {6a 40 68 00 30 00 00 90 02 07 ff 90 01 01 50 90 02 08 6a 00 89 45 90 01 01 ff 90 00 } //01 00 
		$a_00_3 = {b8 4d 5a 00 00 66 39 } //01 00 
		$a_02_4 = {6a 01 6a 01 90 01 01 03 90 01 01 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}