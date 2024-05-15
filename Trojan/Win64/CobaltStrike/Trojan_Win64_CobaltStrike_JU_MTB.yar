
rule Trojan_Win64_CobaltStrike_JU_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 04 24 ff c0 89 04 24 48 63 04 24 48 3b 44 24 } //01 00 
		$a_03_1 = {0f be 0c 0a 33 c1 48 63 0c 24 48 8b 54 24 90 01 01 88 04 0a 8b 44 24 90 01 01 ff c0 89 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}