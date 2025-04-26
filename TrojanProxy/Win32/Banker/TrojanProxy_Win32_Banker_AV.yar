
rule TrojanProxy_Win32_Banker_AV{
	meta:
		description = "TrojanProxy:Win32/Banker.AV,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b d0 83 e2 03 8a 92 ?? ?? 40 00 30 14 38 40 83 f8 11 7c ec ba fd ff ff ff 2b d1 } //10
		$a_01_1 = {80 36 3b 8b 7d f8 b1 15 30 4e 01 b0 cf 30 46 02 b2 97 30 56 03 30 53 03 30 4b 01 30 4b 05 30 43 02 30 43 06 80 33 3b } //10
		$a_03_2 = {83 e3 03 0f b6 9b ?? ?? 40 00 30 58 02 0f b6 09 30 48 03 0f b6 0f 30 48 04 83 c0 06 8d 0c 02 83 f9 12 7c 8a } //10
		$a_01_3 = {5a 71 ab b7 19 5d 84 d4 6e 49 9c f8 5d 61 b8 f6 } //1
		$a_01_4 = {19 7d bb e3 4b 2f e0 b8 0a 22 f8 b9 03 20 e1 ae 0d 3b fe a6 14 65 ae f4 15 65 a7 e7 19 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=20
 
}