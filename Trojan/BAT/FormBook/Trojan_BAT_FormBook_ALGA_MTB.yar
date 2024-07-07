
rule Trojan_BAT_FormBook_ALGA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ALGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 13 05 08 09 11 04 6f 90 01 03 0a 13 06 11 06 28 90 01 03 0a 13 07 07 06 11 07 d2 9c 00 11 04 17 58 90 00 } //2
		$a_01_1 = {4c 00 75 00 6d 00 69 00 6e 00 6f 00 75 00 73 00 46 00 6f 00 72 00 74 00 73 00 } //1 LuminousForts
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}