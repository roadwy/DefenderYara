
rule Trojan_Win32_Zbot_AZB_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 d9 8d be 00 60 05 00 8b 07 09 c0 74 45 8b 5f 04 8d 84 30 60 9a 05 00 01 f3 50 83 c7 08 ff 96 24 9b 05 00 95 8a 07 47 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zbot_AZB_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.AZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e1 02 d3 e0 c1 e1 03 23 c8 33 ce f7 e3 83 ef 72 49 c1 e0 04 23 d9 } //1
		$a_01_1 = {f7 e1 33 f6 d3 ee 0b cf 42 d1 e9 d3 e6 8d 0c 80 d3 e3 8d 93 da 00 00 00 33 c9 8d 0c 89 ba 95 15 de f4 c1 e0 04 42 81 ef 7c 2b 00 00 c1 e7 05 83 e8 24 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}
rule Trojan_Win32_Zbot_AZB_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.AZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 0f fe c6 45 12 ac c6 45 9d 92 c6 45 0d b8 c6 45 b8 ea c6 45 3e 3e c6 45 76 8f c6 45 fc bf c6 45 65 b0 c6 45 cd 24 c6 45 58 24 c6 45 94 d4 c6 45 f5 f8 c6 45 dc 51 c6 45 a8 fa c6 45 d4 fb c6 45 3b 30 c6 45 81 55 c6 45 bc f8 c6 45 57 03 c6 45 fb f0 c6 45 2a c5 c6 45 ad 4a c6 45 33 cb c6 45 93 28 c6 45 8e f0 c6 45 39 b9 c6 45 f7 e9 c6 45 18 1f c6 45 2b e1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}