
rule Trojan_Win64_CobaltStrike_SPA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 eb 8b cb ff c3 c1 90 01 02 8b c2 c1 90 01 02 03 d0 6b 90 01 02 90 02 10 0f b6 8c 3a 90 01 04 41 32 4c 90 01 02 43 88 4c 08 90 01 01 3b 5c 24 20 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}