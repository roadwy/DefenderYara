
rule Trojan_Win64_CobaltStrike_FUJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 38 48 89 44 24 08 33 d2 48 8b 04 24 48 8b 4c 24 08 48 f7 f1 48 8b c2 48 8b 4c 24 30 0f b7 04 41 48 8b 4c 24 20 48 8b 14 24 0f b7 0c 51 33 c8 8b c1 48 8b 4c 24 20 48 8b 14 24 66 89 04 51 } //00 00 
	condition:
		any of ($a_*)
 
}