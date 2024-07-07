
rule Trojan_BAT_FormBook_AZF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 16 2b 28 00 11 14 11 16 18 6f 90 01 03 0a 20 03 02 00 00 28 90 01 03 0a 13 18 11 15 11 18 6f 90 01 03 0a 00 11 16 18 58 13 16 00 11 16 11 14 6f 90 01 03 0a fe 04 13 19 11 19 2d c7 90 00 } //2
		$a_01_1 = {4d 00 6f 00 72 00 69 00 73 00 73 00 43 00 6f 00 64 00 65 00 } //1 MorissCode
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}