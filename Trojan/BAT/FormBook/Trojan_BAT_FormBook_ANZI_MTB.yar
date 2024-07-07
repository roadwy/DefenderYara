
rule Trojan_BAT_FormBook_ANZI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ANZI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 13 04 07 6f 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 de 14 90 00 } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}