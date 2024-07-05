
rule Trojan_Win64_CobaltStrike_AZX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 c2 48 8b 4c 24 68 83 e2 90 01 01 41 8a 54 15 00 41 32 14 04 88 14 01 48 ff c0 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}