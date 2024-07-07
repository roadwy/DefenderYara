
rule Trojan_BAT_FormBook_FDAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.FDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 01 11 0a 11 10 11 13 5d d2 9c } //1
		$a_01_1 = {11 0c 11 0d 61 13 0f } //1
		$a_01_2 = {11 01 11 0b 91 11 13 58 13 0e } //1
		$a_01_3 = {11 07 1f 16 5d 91 13 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}