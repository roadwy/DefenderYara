
rule Trojan_Win64_CobaltStrike_AY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 8b 45 18 48 01 d0 0f b6 00 88 01 83 45 90 01 02 8b 55 90 01 01 8b 05 90 01 04 39 c2 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}