
rule Trojan_BAT_FormBook_AEDS_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AEDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 57 00 16 13 04 2b 3d 00 08 09 11 04 28 90 01 03 06 28 90 01 03 06 90 00 } //2
		$a_01_1 = {53 00 75 00 70 00 } //1 Sup
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}