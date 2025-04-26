
rule Trojan_BAT_Razy_KAB_MTB{
	meta:
		description = "Trojan:BAT/Razy.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 84 30 5f 30 34 00 84 30 5f 30 34 00 84 30 5f 30 34 00 84 30 5f 30 34 00 84 30 5f 30 34 00 84 } //1
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}