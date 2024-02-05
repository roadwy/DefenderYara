
rule Backdoor_Win64_CobaltStrikeLoader_G_MTB{
	meta:
		description = "Backdoor:Win64/CobaltStrikeLoader.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 04 0e 0f b6 c0 83 e8 90 02 01 6b c0 90 02 01 99 f7 ff 8d 04 17 99 f7 ff 88 14 0e 46 83 fe 90 02 01 72 e2 90 00 } //01 00 
		$a_03_1 = {8a 04 37 0f b6 c0 6a 90 02 01 59 2b c8 6b c1 90 02 01 99 f7 fb 8d 04 13 99 f7 fb 88 14 37 47 83 ff 90 02 01 72 e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}