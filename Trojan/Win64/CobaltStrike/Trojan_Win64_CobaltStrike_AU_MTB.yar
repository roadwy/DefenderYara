
rule Trojan_Win64_CobaltStrike_AU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 04 24 0f b6 4c 24 90 01 01 48 8b 54 24 90 01 01 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 90 01 01 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}