
rule VirTool_Win64_Kuronotoz_A_MTB{
	meta:
		description = "VirTool:Win64/Kuronotoz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b c8 ff 15 90 01 04 ff 15 90 01 04 48 8d 90 01 05 ff 15 90 01 04 48 8d 90 01 05 48 8d 90 00 } //01 00 
		$a_03_1 = {41 b8 20 01 00 00 48 8d 90 01 05 48 8d 90 01 05 e8 90 01 04 48 8d 90 01 05 48 8d 90 01 05 e8 90 01 04 48 8d 90 01 05 48 8d 90 00 } //01 00 
		$a_03_2 = {48 8b d8 48 8d 90 01 05 e8 90 01 04 48 8d 90 01 05 48 8d 90 01 05 e8 90 01 04 48 8d 90 01 05 48 8d 90 01 05 e8 90 01 04 4c 8b c3 48 8d 90 01 05 48 8d 90 01 05 e8 90 01 04 48 8d 90 01 05 48 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}