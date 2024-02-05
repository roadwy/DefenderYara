
rule Trojan_Win64_CobaltStrike_MKVG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MKVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 c8 99 f7 fb 0f b6 04 17 30 04 0e 8d 41 90 01 01 99 f7 fb 0f b6 04 17 30 44 0e 90 01 01 48 83 c1 90 01 01 48 39 cd 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}