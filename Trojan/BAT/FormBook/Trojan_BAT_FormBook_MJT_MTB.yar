
rule Trojan_BAT_FormBook_MJT_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 00 72 61 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 20 01 00 00 00 7e 91 02 00 04 7b 7b 02 00 04 3a 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c 04 00 } //4
		$a_03_1 = {38 30 00 00 00 11 00 72 93 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 20 00 00 00 00 7e 91 02 00 04 7b a8 02 00 04 3a c5 ff ff ff 26 20 00 00 00 00 38 ba ff ff ff 11 00 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 13 02 20 02 00 00 00 38 9d ff ff ff } //5
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*5) >=9
 
}