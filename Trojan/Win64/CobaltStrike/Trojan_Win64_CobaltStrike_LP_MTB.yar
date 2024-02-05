
rule Trojan_Win64_CobaltStrike_LP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b c0 99 83 e2 90 01 01 03 c2 83 e0 90 01 01 2b c2 48 63 c8 42 0f b6 04 19 43 32 04 0a 41 88 01 41 ff c0 49 ff c1 41 81 f8 90 01 04 72 d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_LP_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.LP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 48 33 c9 65 48 8b 41 60 48 8b 40 18 48 8b 70 20 } //00 00 
	condition:
		any of ($a_*)
 
}