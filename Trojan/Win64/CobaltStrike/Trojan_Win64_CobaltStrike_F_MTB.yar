
rule Trojan_Win64_CobaltStrike_F_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 90 01 01 41 8a 14 14 32 54 05 90 01 01 88 14 03 48 ff c0 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}