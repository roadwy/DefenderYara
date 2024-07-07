
rule Trojan_BAT_FormBook_ELAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ELAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 25 26 28 90 01 01 00 00 0a 25 26 13 05 90 00 } //2
		$a_03_1 = {11 05 08 6f 90 01 01 00 00 0a 25 26 11 07 20 00 01 00 00 14 14 11 06 74 90 01 01 00 00 1b 6f 90 01 01 00 00 0a 25 26 26 2b 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}