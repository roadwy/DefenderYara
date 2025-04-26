
rule Trojan_BAT_FormBook_NZI_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 60 11 19 16 91 1e 62 60 11 19 17 91 1f 18 62 60 02 65 61 } //2
		$a_01_1 = {61 11 1a 19 58 61 11 2f 61 d2 9c 17 11 09 58 } //1
		$a_01_2 = {1d 5f 91 13 1c 11 1c 19 62 11 1c 1b 63 60 d2 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}