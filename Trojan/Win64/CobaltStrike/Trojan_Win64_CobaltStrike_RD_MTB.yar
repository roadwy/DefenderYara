
rule Trojan_Win64_CobaltStrike_RD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 8b e8 44 8b f3 41 b9 40 00 00 00 41 b8 00 10 00 00 8b d3 33 c9 ff 15 0a ee } //01 00 
		$a_01_1 = {0f 57 c0 48 8d 53 08 48 89 0b 48 8d 48 08 0f 11 02 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_CobaltStrike_RD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 89 4c 24 50 48 8d 44 24 70 48 89 4c 24 48 41 b9 ff 01 0f 00 48 89 4c 24 40 48 8b cb 48 89 44 24 38 c7 44 24 30 01 00 00 00 c7 44 24 28 03 00 00 00 c7 44 24 20 } //00 00 
	condition:
		any of ($a_*)
 
}