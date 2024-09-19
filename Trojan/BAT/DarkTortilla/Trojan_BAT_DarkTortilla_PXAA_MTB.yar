
rule Trojan_BAT_DarkTortilla_PXAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.PXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 02 03 1c da 14 d0 ?? 00 00 01 28 ?? 00 00 0a 72 ?? ?? 00 70 17 8d ?? 00 00 01 25 16 02 25 0b 03 17 da 25 0c 9a a2 25 0d 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 13 04 28 ?? 00 00 0a 11 04 16 91 2d 02 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}