
rule Trojan_Win64_BumbleBee_BM_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 6c 6f 4f 45 45 69 48 6a } //01 00 
		$a_01_1 = {50 76 68 67 4f 71 } //01 00 
		$a_01_2 = {4e 79 47 6c 69 73 44 49 4b 4e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBee_BM_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 57 59 37 32 } //01 00 
		$a_01_1 = {51 43 59 5a 6e 36 37 34 37 48 } //01 00 
		$a_01_2 = {51 4f 55 58 49 33 31 } //01 00 
		$a_01_3 = {52 6f 4f 45 69 7a 74 4a 76 57 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBee_BM_MTB_3{
	meta:
		description = "Trojan:Win64/BumbleBee.BM!MTB,SIGNATURE_TYPE_PEHSTR,09 00 09 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 4c 41 49 33 } //01 00 
		$a_01_1 = {47 48 6a 61 63 75 64 52 } //01 00 
		$a_01_2 = {47 78 42 6c 4f 4f } //05 00 
		$a_01_3 = {53 65 74 56 50 41 43 6f 6e } //01 00 
		$a_01_4 = {59 43 6c 68 6a 36 33 34 66 78 67 7a } //00 00 
	condition:
		any of ($a_*)
 
}