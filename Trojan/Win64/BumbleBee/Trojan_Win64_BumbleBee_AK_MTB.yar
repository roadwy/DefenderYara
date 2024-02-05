
rule Trojan_Win64_BumbleBee_AK_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {48 53 6f 68 30 35 49 71 36 } //02 00 
		$a_01_1 = {50 7a 7a 44 34 36 39 52 30 } //02 00 
		$a_01_2 = {72 69 62 20 67 6f 64 20 64 65 64 69 63 61 74 65 } //02 00 
		$a_01_3 = {6b 6f 6e 72 61 64 20 72 65 70 61 69 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBee_AK_MTB_2{
	meta:
		description = "Trojan:Win64/BumbleBee.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 58 49 30 37 33 42 79 7a } //02 00 
		$a_01_1 = {45 64 48 56 6e 74 71 64 57 74 } //02 00 
		$a_01_2 = {50 65 65 6b 4e 61 6d 65 64 50 69 70 65 } //02 00 
		$a_01_3 = {48 65 61 70 57 61 6c 6b } //02 00 
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_BumbleBee_AK_MTB_3{
	meta:
		description = "Trojan:Win64/BumbleBee.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6e 78 68 55 4f 59 7a 66 61 63 } //02 00 
		$a_01_1 = {72 61 6e 6b 20 77 69 74 68 6f 75 74 20 73 74 75 63 6b } //02 00 
		$a_01_2 = {63 69 72 63 75 6c 61 72 20 6e 69 67 68 74 6d 61 72 65 20 67 61 6c 65 } //02 00 
		$a_01_3 = {53 75 73 70 65 6e 64 54 68 72 65 61 64 } //00 00 
	condition:
		any of ($a_*)
 
}