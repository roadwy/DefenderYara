
rule Trojan_Win64_CobaltStrike_HNF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 8b 4c 24 20 83 e1 05 48 63 c9 48 8d 15 90 01 04 0f b6 0c 0a 33 c1 48 63 4c 24 20 48 8d 15 90 01 04 88 04 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}