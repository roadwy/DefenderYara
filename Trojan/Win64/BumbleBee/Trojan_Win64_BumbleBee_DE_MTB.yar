
rule Trojan_Win64_BumbleBee_DE_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 79 68 72 77 31 34 30 77 62 33 2e 64 6c 6c } //01 00 
		$a_01_1 = {45 56 4a 62 36 38 4a } //01 00 
		$a_01_2 = {54 79 66 43 6e 36 32 37 } //01 00 
		$a_01_3 = {58 75 52 4d 6c 36 33 36 4b 61 51 66 } //01 00 
		$a_01_4 = {61 6a 77 47 77 52 4b 68 4c 69 } //00 00 
	condition:
		any of ($a_*)
 
}