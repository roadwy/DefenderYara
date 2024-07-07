
rule Trojan_BAT_FormBook_AHNY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AHNY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 16 4c 01 00 0c 2b 3c 00 06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 1f 16 5d 91 61 28 90 01 03 0a 06 08 17 58 06 8e 69 5d 91 90 00 } //2
		$a_01_1 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 43 00 6f 00 6d 00 75 00 6e 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //1 NetworkComunication
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}