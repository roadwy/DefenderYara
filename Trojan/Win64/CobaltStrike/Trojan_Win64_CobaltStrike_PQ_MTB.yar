
rule Trojan_Win64_CobaltStrike_PQ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c8 83 f1 28 0f af c8 41 8b d1 45 8b c1 c1 ea 18 41 c1 e8 10 89 8b 90 02 04 48 63 8b 90 02 04 8b 83 90 02 04 33 83 90 02 04 83 e8 12 01 43 90 02 04 8b 43 90 02 04 29 83 90 02 04 48 8b 83 90 02 04 88 14 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}