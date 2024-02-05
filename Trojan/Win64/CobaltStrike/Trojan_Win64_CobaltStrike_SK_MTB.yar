
rule Trojan_Win64_CobaltStrike_SK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 89 d8 48 89 d9 48 c1 f8 90 01 01 48 c1 f9 90 01 01 31 d8 31 c8 48 89 d9 48 c1 f9 90 01 01 31 c8 30 44 1a 90 01 01 48 90 01 03 4c 39 c3 75 90 00 } //01 00 
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}