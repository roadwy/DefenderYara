
rule Trojan_BAT_AsyncRat_ABNV_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ABNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {04 08 07 28 90 01 03 0a 25 26 16 6f 90 01 03 0a 25 26 13 05 12 05 28 90 01 03 0a 25 26 6f 90 01 03 0a 00 07 09 12 01 28 90 01 03 0a 25 26 13 06 11 06 2d c8 90 00 } //4
		$a_01_1 = {42 69 74 6d 61 70 } //1 Bitmap
		$a_01_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}