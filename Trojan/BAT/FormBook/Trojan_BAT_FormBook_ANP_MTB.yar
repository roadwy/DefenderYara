
rule Trojan_BAT_FormBook_ANP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ANP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 09 11 04 28 90 01 03 06 28 90 01 03 06 00 28 90 01 03 06 28 90 01 03 06 28 90 01 03 06 00 07 06 28 90 01 03 06 d2 9c 00 11 04 17 58 90 00 } //2
		$a_01_1 = {4d 00 61 00 74 00 63 00 68 00 69 00 6e 00 67 00 50 00 61 00 69 00 72 00 73 00 47 00 61 00 6d 00 65 00 } //1 MatchingPairsGame
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}