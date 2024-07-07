
rule Trojan_Win32_TrickbotCrypt_SO_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 a3 90 01 04 8b 0d 90 01 04 3b 4d 90 01 01 0f 83 90 01 04 8b 45 90 01 01 83 c0 01 8b 4d 90 01 01 33 d2 f7 31 89 55 90 01 01 8b 55 90 01 01 03 55 90 01 01 33 c0 8a 02 8b 4d 90 01 01 03 c8 8b 75 90 01 01 8b c1 33 d2 f7 36 89 55 90 01 01 8b 55 90 01 01 03 55 90 01 01 8a 02 90 00 } //1
		$a_03_1 = {8a 0a 03 c1 8b 4d 90 01 01 33 d2 f7 31 89 55 90 01 01 8b 15 90 01 04 8b 02 8b 4d 90 01 01 33 d2 8a 14 01 8b 45 90 01 01 03 45 90 01 01 33 c9 8a 08 33 d1 a1 90 01 04 8b 08 8b 45 18 88 14 08 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}