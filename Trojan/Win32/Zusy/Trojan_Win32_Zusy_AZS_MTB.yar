
rule Trojan_Win32_Zusy_AZS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 56 0e 8d 76 10 8b c2 47 c1 e8 18 0f b6 0c 85 70 5c 5f 00 0f b6 46 ff 8b 0c 8d 70 50 5f 00 0f b6 04 85 70 5c 5f 00 33 0c 85 70 48 5f 00 0f b6 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zusy_AZS_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.AZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 ca c1 ea 08 33 34 8d c0 6a 47 00 0f b6 d2 8b ce 33 48 18 8b 14 95 c0 6e 47 00 89 75 f8 89 4d f8 8b 4d e4 c1 e9 10 0f b6 c9 33 14 8d c0 72 47 00 8b 4d ec c1 e9 18 33 14 8d c0 76 47 00 0f b6 cb 33 14 8d c0 6a 47 00 } //2
		$a_01_1 = {8b cb 33 50 10 c1 e9 10 89 55 f0 0f b6 d1 8b 4d ec 8b 14 95 c0 72 47 00 c1 e9 08 0f b6 c9 33 14 8d c0 6e 47 00 8b 4d dc c1 e9 18 33 14 8d c0 76 47 00 89 55 fc 8b 55 e4 8b 7d fc 0f b6 ca 33 3c 8d c0 6a 47 00 8b cf 33 48 14 89 7d fc } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win32_Zusy_AZS_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.AZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 60 60 24 10 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d } //2
		$a_01_1 = {c6 85 06 ff ff ff 52 c6 85 07 ff ff ff 68 c6 85 08 ff ff ff 63 c6 85 09 ff ff ff 32 c6 85 0a ff ff ff 74 c6 85 0b ff ff ff 4f c6 85 0c ff ff ff 59 c6 85 0d ff ff ff 57 c6 85 0e ff ff ff 31 c6 85 0f ff ff ff 6c c6 85 10 ff ff ff 49 c6 85 11 ff ff ff 43 c6 85 12 ff ff ff 52 c6 85 13 ff ff ff 30 c6 85 14 ff ff ff 59 c6 85 15 ff ff ff 58 c6 85 16 ff ff ff 4e c6 85 17 ff ff ff 72 c6 85 18 ff ff ff 54 c6 85 19 ff ff ff 6d c6 85 1a ff ff ff 46 c6 85 1b ff ff ff 74 c6 85 1c ff ff ff 5a c6 85 1d ff ff ff 51 c6 85 1e ff ff ff 3d c6 85 1f ff ff ff 3d } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}