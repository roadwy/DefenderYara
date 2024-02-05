
rule Trojan_MacOS_NukeSped_B_MTB{
	meta:
		description = "Trojan:MacOS/NukeSped.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 72 61 62 62 65 64 6c 79 2e 63 6c 75 62 2f 62 6f 61 72 64 2e 70 68 70 } //01 00 
		$a_00_1 = {63 72 61 79 70 6f 74 2e 6c 69 76 65 2f 62 6f 61 72 64 2e 70 68 70 } //01 00 
		$a_00_2 = {69 6e 64 61 67 61 74 6f 72 2e 63 6c 75 62 2f 62 6f 61 72 64 2e 70 68 70 } //01 00 
		$a_00_3 = {0f 10 0c 13 0f 10 54 13 10 0f 10 5c 13 20 0f 10 64 13 30 0f 57 c8 0f 57 d0 0f 11 0c 13 0f 11 54 13 10 0f 57 d8 0f 57 e0 0f 11 5c 13 20 0f 11 64 13 30 48 83 c2 40 48 83 c6 02 75 c4 eb 02 } //00 00 
		$a_00_4 = {5d 04 00 } //00 7c 
	condition:
		any of ($a_*)
 
}