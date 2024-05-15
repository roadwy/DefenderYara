
rule Trojan_Win64_CobaltStrike_NJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c2 0f af c2 ff c2 01 05 90 01 04 8b 05 90 01 04 05 90 01 04 31 43 90 01 01 8b 8b 90 01 04 33 4b 90 01 01 8b 05 90 01 04 81 e9 90 01 04 0f af c1 89 05 90 01 04 8b 05 90 01 04 83 f0 90 01 01 01 83 90 01 04 3b 53 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}