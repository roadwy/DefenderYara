
rule Trojan_Win32_Emotet_CI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff d6 55 e8 90 01 04 8b c8 33 d2 8b c7 f7 f1 8a 04 1f 83 c4 04 8a 54 55 00 32 c2 88 04 1f 8b 44 24 1c 47 3b f8 75 90 00 } //1
		$a_02_1 = {53 8b 5c 24 10 57 8b 7c 24 18 53 e8 90 01 04 8b c8 33 d2 8b c6 f7 f1 46 83 c4 04 8a 14 53 30 54 3e ff 3b f5 75 90 00 } //1
		$a_02_2 = {6a 0a 8b 8d 50 ff ff ff e8 90 01 04 8b 8d 50 ff ff ff e8 c6 06 00 00 8b 45 fc 33 d2 b9 27 00 00 00 f7 f1 8b 45 08 0f b7 0c 50 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}