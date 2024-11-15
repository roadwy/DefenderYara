
rule Trojan_BAT_FormBook_NZK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 00 2b 4a 09 16 fe 02 13 05 11 05 2c 40 00 03 12 02 } //2
		$a_01_1 = {59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2f 00 03 19 } //1
		$a_01_2 = {04 fe 04 16 fe 01 13 08 11 08 2c 02 2b 2e 00 07 17 58 0b 07 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}