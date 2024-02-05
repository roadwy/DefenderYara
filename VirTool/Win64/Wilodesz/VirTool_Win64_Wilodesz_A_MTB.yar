
rule VirTool_Win64_Wilodesz_A_MTB{
	meta:
		description = "VirTool:Win64/Wilodesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 04 01 00 00 ff 15 90 01 04 48 8d 15 90 01 04 48 8d 8c 90 01 05 ff 15 90 01 04 45 33 c0 48 8d 94 90 01 05 48 90 01 04 ff 15 90 00 } //01 00 
		$a_03_1 = {ba 00 00 00 40 8b f0 ff 15 90 01 04 48 8b d8 48 83 f8 ff 75 90 00 } //01 00 
		$a_03_2 = {48 8b cb ff 15 90 01 04 48 8b 0d e9 35 00 00 48 8d 15 90 01 04 e8 c5 90 01 03 48 8b c8 48 8d 15 90 01 04 ff 15 90 01 04 48 8d 0d 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}