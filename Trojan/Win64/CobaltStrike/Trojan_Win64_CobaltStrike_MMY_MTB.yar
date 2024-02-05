
rule Trojan_Win64_CobaltStrike_MMY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 89 c1 44 89 c0 49 ff c0 48 3b 4c 24 90 01 01 4c 8b 54 24 90 01 01 73 90 01 01 99 41 f7 f9 48 8d 05 90 01 04 48 63 d2 8a 04 10 48 8b 54 24 90 01 01 32 04 0a 41 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}