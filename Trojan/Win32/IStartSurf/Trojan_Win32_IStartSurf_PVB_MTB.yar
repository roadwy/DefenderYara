
rule Trojan_Win32_IStartSurf_PVB_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.PVB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {8b 55 b8 c1 ea 05 03 55 90 33 ca 8b 45 bc 2b c1 89 45 bc 8b 4d a4 2b 4d 8c 89 4d a4 eb } //1
		$a_01_1 = {ba 04 00 00 00 6b c2 00 8b 4d b4 8b 55 bc 89 14 01 b8 04 00 00 00 c1 e0 00 8b 4d b4 8b 55 b8 89 14 01 e9 } //1
		$a_01_2 = {8b 45 b8 c1 e8 05 03 45 90 33 c8 8b 55 bc 2b d1 89 55 bc 8b 45 a4 2b 45 8c 89 45 a4 eb } //1
		$a_01_3 = {b9 04 00 00 00 6b d1 00 8b 45 b4 8b 4d bc 89 0c 10 ba 04 00 00 00 c1 e2 00 8b 45 b4 8b 4d b8 89 0c 10 e9 } //1
		$a_01_4 = {8b 4d dc c1 e9 05 03 4d b8 33 c1 8b 4d e4 2b c8 89 4d e4 8b 45 d8 2b 45 b4 89 45 d8 eb } //1
		$a_01_5 = {6a 04 58 6b c0 00 8b 4d e0 8b 55 e4 89 14 01 6a 04 58 c1 e0 00 8b 4d e0 8b 55 dc 89 14 01 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}