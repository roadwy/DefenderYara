
rule Trojan_Win64_CobaltStrike_YAB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 90 01 01 48 63 0c 24 0f be 04 08 48 8b 4c 24 90 01 01 48 63 54 24 04 0f be 0c 11 31 c8 88 c2 48 8b 44 24 08 48 63 0c 24 88 14 08 8b 44 24 04 83 c0 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}