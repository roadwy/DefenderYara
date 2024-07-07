
rule Trojan_Win32_Tinba_V_MTB{
	meta:
		description = "Trojan:Win32/Tinba.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 45 f5 24 90 01 01 88 45 f5 8b 4d f0 8b 55 f8 8a 45 e3 38 04 0a 74 90 01 01 8d 45 f5 8a 4d f7 88 c2 08 d1 88 4d f7 8b 45 f0 8a 4d f5 80 f1 90 01 01 88 4d f5 8b 75 dc 01 f0 89 45 f0 eb 90 00 } //2
		$a_02_1 = {8d 45 ec 0f b7 4d e2 8b 55 9c 01 ca 8b 4d a4 29 ca 66 89 d6 8b 55 d0 66 89 32 8b 55 ac 31 c2 89 55 ec 8a 5d b3 80 cb 90 01 01 88 5d b3 8d 45 e8 66 8b 4d ba 66 89 c2 66 21 d1 66 89 4d ba b0 90 01 01 b9 90 01 04 8b 55 d0 81 c2 90 01 04 8a 65 b3 2b 4d e8 89 55 d0 28 e0 88 45 b3 89 4d e8 e9 90 00 } //2
		$a_02_2 = {8b 4d c8 8b 55 f0 21 c2 89 55 f0 c7 45 e8 90 01 04 81 c1 90 01 04 89 4d c8 8d 45 e8 8b 4d cc 66 8b 55 be 66 81 c2 90 01 02 8a 5d 9b 66 89 55 be 88 c7 08 fb 88 5d 9b 8b 85 90 01 04 01 c1 89 4d cc e9 90 00 } //2
		$a_02_3 = {8b 45 94 8b 4d ec 81 e1 90 01 04 89 4d ec 3b 85 90 01 04 74 90 01 01 8d 45 ec 8b 4d 90 90 89 ca 81 c2 90 01 04 c7 45 ec 90 01 04 89 55 90 90 8a 19 8b 4d 8c 89 ca 81 c2 90 01 04 89 55 8c 88 19 8b 4d dc 31 c1 89 4d ec 8b 45 94 8b 8d 90 01 04 01 c8 8b 55 a4 81 c2 90 01 04 89 45 94 89 55 a4 eb 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=4
 
}