
rule Trojan_Win64_BumbleBee_PCC_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.PCC!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 8b ce 89 74 24 28 4c 8b c5 41 8b d7 89 44 24 20 48 8b cf 41 ff d4 } //01 00 
		$a_01_1 = {4d 8b cf 44 89 74 24 28 4c 8b c5 41 8b d4 89 44 24 20 48 8b ce 41 ff d5 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 45 76 65 6e 74 } //01 00 
		$a_01_3 = {51 4f 6d 50 48 68 39 57 4f } //00 00 
	condition:
		any of ($a_*)
 
}