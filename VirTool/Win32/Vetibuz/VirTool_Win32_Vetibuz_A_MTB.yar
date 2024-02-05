
rule VirTool_Win32_Vetibuz_A_MTB{
	meta:
		description = "VirTool:Win32/Vetibuz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {6a 04 68 00 10 00 00 68 a0 86 01 00 6a 00 ff 15 } //01 00 
		$a_02_1 = {8b f0 89 8d 90 01 01 c8 ff ff 90 02 05 85 c9 90 02 02 8d 85 90 01 01 c8 ff ff 50 68 a0 86 01 00 56 53 90 02 02 85 c0 90 02 02 8b 8d 90 01 01 c8 ff ff 90 00 } //01 00 
		$a_00_2 = {76 69 72 75 73 } //00 00 
	condition:
		any of ($a_*)
 
}