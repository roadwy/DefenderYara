
rule Trojan_BAT_FormBook_AEDJ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AEDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_2 = {47 00 61 00 6d 00 65 00 73 00 74 00 61 00 74 00 73 00 42 00 61 00 73 00 65 00 } //1 GamestatsBase
		$a_01_3 = {41 58 58 56 43 53 56 46 } //1 AXXVCSVF
		$a_01_4 = {62 00 6f 00 61 00 74 00 } //2 boat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=6
 
}