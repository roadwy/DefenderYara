
rule Trojan_Win32_SmokeLoader_D_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 ff 8b 45 08 0f be 14 10 69 d2 } //2
		$a_03_1 = {03 ce 8b 45 0c 03 45 90 01 01 88 08 0f be 4d 90 01 01 8b 55 0c 03 55 90 01 01 0f b6 02 2b c1 8b 4d 0c 03 4d 90 01 01 88 01 eb 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_Win32_SmokeLoader_D_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 84 38 4b 13 01 00 8b 0d 90 01 04 88 04 39 75 06 ff 15 90 01 04 47 3b 3d 90 01 04 72 d0 90 00 } //1
		$a_03_1 = {d3 ef 89 45 e0 c7 05 90 01 04 ee 3d ea f4 03 7d e4 8b 45 e0 31 45 fc 33 7d fc 90 00 } //1
		$a_03_2 = {31 7d fc 8b 45 fc 29 45 f4 81 c3 47 86 c8 61 ff 4d e8 0f 85 90 01 01 fe ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_SmokeLoader_D_MTB_3{
	meta:
		description = "Trojan:Win32/SmokeLoader.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ca 8b c2 c1 e8 05 c1 e1 04 03 4d ec 03 c3 33 c1 33 45 fc 89 45 0c 8b 45 0c 01 05 90 01 04 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 c7 90 00 } //10
		$a_03_1 = {55 8b ec 51 56 be 90 01 04 56 c6 05 90 01 04 33 c6 05 90 01 04 32 c6 05 90 01 04 6c c6 05 90 01 04 6e c6 05 90 01 04 6b c6 05 90 01 04 65 c6 05 90 01 04 6c c6 05 90 01 04 65 c6 05 90 01 04 72 c6 05 90 01 04 2e c6 05 90 01 04 64 c6 05 90 01 04 6c 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}