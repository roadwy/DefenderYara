
rule Trojan_Win64_BumbleBee_BV_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 6c 5a 45 55 45 42 } //02 00 
		$a_01_1 = {52 41 58 78 79 4c 38 38 4d 44 } //01 00 
		$a_01_2 = {47 65 74 53 74 64 48 61 6e 64 6c 65 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 46 69 6c 65 41 } //01 00 
		$a_01_4 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 } //01 00 
		$a_01_5 = {57 61 69 74 4e 61 6d 65 64 50 69 70 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}