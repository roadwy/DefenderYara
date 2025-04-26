
rule Trojan_BAT_SnakeKeylogger_SMI_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {00 12 02 28 da 00 00 0a 13 05 12 02 28 db 00 00 0a 13 06 12 02 28 dc 00 00 0a 13 07 1d 13 0f 38 38 ff ff ff 03 11 05 16 61 d2 6f dd 00 00 0a } //1
		$a_81_1 = {24 34 31 62 37 35 62 66 65 2d 65 61 36 38 2d 34 32 31 65 2d 38 32 66 33 2d 63 35 30 63 38 66 34 37 65 38 30 61 } //1 $41b75bfe-ea68-421e-82f3-c50c8f47e80a
		$a_81_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_3 = {42 69 74 6d 61 70 } //1 Bitmap
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}