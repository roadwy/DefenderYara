
rule Trojan_BAT_Ocatohcy_DA_MTB{
	meta:
		description = "Trojan:BAT/Ocatohcy.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 09 9a 6f 90 01 03 0a 13 04 11 04 6f 90 01 03 0a 06 6f 90 01 03 0a 31 05 11 04 0a 09 0c 09 17 58 0d 09 07 8e 69 32 d8 90 00 } //20
		$a_81_1 = {4d 53 65 63 6f 6e 64 4e 75 6d 62 65 72 4c 69 73 74 } //1 MSecondNumberList
		$a_81_2 = {54 72 75 73 74 69 72 79 20 53 6f 66 74 } //1 Trustiry Soft
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=23
 
}