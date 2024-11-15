
rule Trojan_BAT_DarkTortilla_YPAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.YPAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 18 9a 14 72 24 27 00 70 17 8d ?? 00 00 01 25 16 1f 18 8c ?? 00 00 01 a2 14 14 14 28 ?? 00 00 0a 14 72 36 27 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 16 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 14 72 16 27 00 70 18 8d ?? 00 00 01 25 17 7e ?? 00 00 04 a2 25 13 07 14 14 18 8d ?? 00 00 01 25 17 17 9c 25 13 08 17 28 ?? 00 00 0a 26 11 08 17 91 2d 02 } //4
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}