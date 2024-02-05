
rule Trojan_Win64_LotusBlossom_D_dha{
	meta:
		description = "Trojan:Win64/LotusBlossom.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {7b 42 36 45 35 36 46 30 43 2d 46 31 42 37 35 42 37 46 7d } //01 00 
		$a_81_1 = {4c 6f 61 64 44 4c 4c 34 2e 64 6c 6c } //01 00 
		$a_81_2 = {6e 73 73 64 6c 6c 40 40 33 48 41 } //01 00 
		$a_81_3 = {53 74 61 72 74 55 70 } //01 00 
		$a_81_4 = {66 6e 61 62 63 73 73 64 6c 6c 40 40 59 41 48 58 5a } //00 00 
	condition:
		any of ($a_*)
 
}