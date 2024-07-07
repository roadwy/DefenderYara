
rule Trojan_BAT_Remcos_EZ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 09 5a 1a 11 04 5a 58 28 90 01 03 0a 13 05 08 6f 90 01 03 0a 08 6f 90 01 03 0a 09 5a 1a 11 04 5a 58 11 05 28 90 01 03 0a 00 00 11 04 17 58 13 04 11 04 07 6f 90 01 03 0a 17 59 fe 02 16 fe 01 13 06 11 06 2d ae 90 00 } //10
		$a_81_1 = {43 6f 6e 76 65 72 74 54 6f 41 6c 70 68 61 42 69 74 6d 61 70 } //1 ConvertToAlphaBitmap
		$a_81_2 = {4d 61 6e 69 6e 61 } //1 Manina
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}