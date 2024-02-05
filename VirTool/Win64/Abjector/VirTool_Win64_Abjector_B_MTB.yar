
rule VirTool_Win64_Abjector_B_MTB{
	meta:
		description = "VirTool:Win64/Abjector.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {65 48 8b 04 25 30 00 00 00 48 85 c0 0f 84 90 02 04 48 8b 48 60 48 85 c9 0f 84 90 02 08 48 8b 90 01 01 18 90 00 } //01 00 
		$a_02_1 = {0f b6 0a 84 90 02 05 c1 90 01 01 07 90 02 04 0f be 90 02 05 33 90 01 01 0f b6 90 01 01 84 90 00 } //01 00 
		$a_02_2 = {41 b8 00 30 00 00 90 02 03 44 8d 49 40 90 02 05 90 01 01 0f b7 90 01 01 14 90 02 08 ff 90 00 } //01 00 
		$a_02_3 = {ba 01 00 00 00 48 03 90 02 04 44 8b c2 90 02 03 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}