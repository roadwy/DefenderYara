
rule Trojan_Win32_RedLineStealer_PK_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {29 45 fc 8b 4d fc c1 e1 90 01 01 03 4d f0 8b 45 fc 03 45 f8 89 45 0c 8b 55 fc 83 0d 90 01 04 ff 8b c2 c1 e8 90 01 01 03 45 e4 68 90 01 04 89 45 08 33 45 0c c7 05 90 01 08 33 c1 90 00 } //1
		$a_03_1 = {8b 44 24 20 89 44 24 14 8b 44 24 24 01 44 24 14 8b 44 24 20 c1 e8 90 01 01 89 44 24 10 8b 44 24 10 03 44 24 38 c7 05 90 01 08 33 44 24 14 33 c6 81 3d 90 01 08 89 44 24 10 0f 85 90 00 } //1
		$a_01_2 = {8a 8c 0d c4 5b ff ff 88 8d 8b 5b ff ff 0f b6 85 8b 5b ff ff 8b 0d e8 2b 48 00 03 8d 14 58 ff ff 0f be 11 33 d0 a1 e8 2b 48 00 03 85 14 58 ff ff 88 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}