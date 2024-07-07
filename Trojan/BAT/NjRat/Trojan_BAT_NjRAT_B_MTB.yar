
rule Trojan_BAT_NjRAT_B_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 06 14 72 90 01 03 70 16 8d 90 01 01 00 00 01 14 14 14 28 90 01 01 00 00 0a 14 72 90 01 03 70 18 8d 90 01 01 00 00 01 13 90 01 01 11 90 01 01 16 14 a2 00 11 90 01 01 17 14 a2 00 11 90 01 01 14 14 14 28 90 00 } //2
		$a_01_1 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}