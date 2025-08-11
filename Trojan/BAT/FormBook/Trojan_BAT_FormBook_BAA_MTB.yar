
rule Trojan_BAT_FormBook_BAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 6f 47 02 00 0a 26 04 07 08 91 6f 48 02 00 0a 08 17 58 0c 08 03 32 e7 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_BAT_FormBook_BAA_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 28 07 00 00 06 0a 73 0a 00 00 0a 25 06 28 05 00 00 06 6f 0b 00 00 0a 0b dd 08 } //1
		$a_01_1 = {02 03 1f 1f 5f 63 02 1e 03 59 1f 1f 5f 62 60 d2 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}