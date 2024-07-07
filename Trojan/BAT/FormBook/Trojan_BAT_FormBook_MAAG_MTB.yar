
rule Trojan_BAT_FormBook_MAAG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MAAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 09 09 5d 13 0a 11 09 09 5b 13 0b 08 11 0a 11 0b 6f 90 01 01 00 00 0a 13 0c 07 11 05 12 0c 28 90 01 01 00 00 0a 9c 11 05 17 58 13 05 00 11 09 17 58 13 09 11 09 09 11 04 5a fe 04 13 0d 11 0d 2d c1 90 00 } //1
		$a_01_1 = {6c 00 6f 00 2e 00 41 00 34 00 } //1 lo.A4
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}