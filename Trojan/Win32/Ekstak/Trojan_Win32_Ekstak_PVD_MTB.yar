
rule Trojan_Win32_Ekstak_PVD_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 4d ec 8b 55 ec 03 51 3c 89 55 fc b8 90 01 04 3d 90 01 04 0f 84 90 01 04 ba 90 01 04 81 fa 90 01 04 0f 84 90 01 04 8b 45 fc 8b 4d ec 03 48 28 89 4d f0 90 00 } //3
		$a_02_1 = {33 d1 d3 e2 81 fa a3 de 43 e4 0f 84 b3 00 00 00 f7 c2 fc 0f a1 19 e9 90 09 0b 00 b9 90 01 04 53 b8 90 00 } //3
		$a_02_2 = {33 d3 c1 ea 02 d3 d8 f7 c2 e7 c8 76 b3 0f 84 90 09 12 00 a5 b8 90 01 04 50 3d 90 01 04 0f 84 90 00 } //3
		$a_02_3 = {a5 d3 c0 81 e2 90 01 04 c1 e2 03 85 d3 0f 92 c3 e9 90 09 06 00 8d 3d 90 00 } //3
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*3+(#a_02_2  & 1)*3+(#a_02_3  & 1)*3) >=3
 
}