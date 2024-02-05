
rule Trojan_Win64_CobaltStrike_LJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {b9 60 ea 00 00 ff d3 eb f7 } //01 00 
		$a_01_1 = {74 65 6d 70 2e 64 6c 6c } //01 00 
		$a_01_2 = {53 74 61 72 74 57 } //01 00 
		$a_01_3 = {44 6c 6c 4d 61 69 6e } //01 00 
		$a_01_4 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}