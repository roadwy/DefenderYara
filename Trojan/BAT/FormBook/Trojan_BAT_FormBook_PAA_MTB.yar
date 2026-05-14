
rule Trojan_BAT_FormBook_PAA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 16 02 7b 0b 00 00 04 7e 54 00 00 04 25 2d 17 26 } //2
		$a_01_1 = {20 00 3e 01 00 28 0f 00 00 06 } //1
		$a_81_2 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}