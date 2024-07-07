
rule Trojan_BAT_FormBook_YRM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.YRM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 07 11 05 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 06 11 06 2d d5 90 00 } //1
		$a_01_1 = {41 00 6c 00 65 00 72 00 6f 00 } //1 Alero
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}