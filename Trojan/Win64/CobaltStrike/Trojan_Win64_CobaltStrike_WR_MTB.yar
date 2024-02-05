
rule Trojan_Win64_CobaltStrike_WR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 89 c1 31 c0 39 c3 7e 90 01 01 48 89 c2 83 e2 03 8a 14 17 32 14 06 41 88 14 01 48 ff c0 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}