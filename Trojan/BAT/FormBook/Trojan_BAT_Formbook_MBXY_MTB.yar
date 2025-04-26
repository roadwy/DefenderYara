
rule Trojan_BAT_Formbook_MBXY_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MBXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 01 28 ?? 01 00 0a 9c 25 17 0f 01 28 ?? 01 00 0a 9c 25 18 0f 01 28 ?? 01 00 0a 9c 0d 02 09 04 } //10
		$a_01_1 = {4c 00 6f 00 61 00 64 } //1
		$a_01_2 = {50 72 6f 63 65 73 73 42 69 74 6d 61 70 } //1 ProcessBitmap
		$a_01_3 = {47 65 74 50 69 78 65 6c 43 6f 6c 6f 72 } //1 GetPixelColor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}