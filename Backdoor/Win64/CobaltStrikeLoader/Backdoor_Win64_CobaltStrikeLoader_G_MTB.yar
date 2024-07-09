
rule Backdoor_Win64_CobaltStrikeLoader_G_MTB{
	meta:
		description = "Backdoor:Win64/CobaltStrikeLoader.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0e 0f b6 c0 83 e8 [0-01] 6b c0 [0-01] 99 f7 ff 8d 04 17 99 f7 ff 88 14 0e 46 83 fe [0-01] 72 e2 } //1
		$a_03_1 = {8a 04 37 0f b6 c0 6a [0-01] 59 2b c8 6b c1 [0-01] 99 f7 fb 8d 04 13 99 f7 fb 88 14 37 47 83 ff [0-01] 72 e0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}