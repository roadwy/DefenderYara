
rule Trojan_BAT_Dcstl_NF_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 6f 65 00 00 0a 73 ?? ?? ?? 0a 0a 06 28 ?? ?? ?? 06 0b 07 2c 02 07 2a 7e ?? ?? ?? 04 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 0b } //5
		$a_01_1 = {63 6f 73 74 75 72 61 2e 6d 65 74 61 64 61 74 61 } //1 costura.metadata
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {4c 00 6f 00 57 00 69 00 42 00 6f 00 74 00 } //1 LoWiBot
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}