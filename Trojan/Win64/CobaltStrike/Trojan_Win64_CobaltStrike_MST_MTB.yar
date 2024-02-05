
rule Trojan_Win64_CobaltStrike_MST_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 8b 84 24 f8 00 00 00 8b 0c 03 41 33 8c 24 90 01 04 49 8b 84 24 90 01 04 89 0c 03 49 81 bc 24 90 01 08 74 90 01 01 49 83 8c 24 18 01 00 00 90 01 01 49 69 4c 24 30 90 01 04 49 8b 84 24 90 01 04 48 83 c3 04 48 35 90 01 04 49 89 44 24 40 41 8b 84 24 90 01 04 41 01 84 24 90 01 04 49 8b 04 24 48 89 48 30 48 81 fb 90 01 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}