
rule Trojan_Win32_Emotet_EK{
	meta:
		description = "Trojan:Win32/Emotet.EK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 34 35 03 0e 6c 7c 8b 4c 24 10 8b 54 24 14 89 11 89 44 24 ?? eb 99 8b 44 24 ?? 8b 4c 24 ?? 89 c2 81 f2 e7 c1 4e 0c 89 54 24 ?? 89 4c 24 ?? 8b 54 24 ?? 8b 74 24 ?? 66 8b 7c 24 ?? 31 db 89 44 24 0c b8 e7 2d 62 a5 89 4c 24 ?? 8b 4c 24 0c 29 c8 8b 4c 24 ?? 19 cb 66 89 7c 24 ?? 31 f3 31 d0 09 d8 89 44 24 ?? 74 af e9 74 ff ff ff } //1
		$a_03_1 = {8b 45 c0 8b 4d c4 ba 41 43 96 5f be 71 43 96 5f 8b 7d ?? 8b 5d ?? 2b 75 ?? 89 45 ?? 89 c8 89 4d ?? 31 c9 89 55 ?? 89 ca f7 f6 8b 4d ?? 29 d9 81 c7 c4 bc 69 a0 8b 75 ?? 21 fe 8b 7d } //1
		$a_03_2 = {39 cf 0f 47 f2 8b 0d ?? ?? ?? ?? 8b 55 b8 01 d7 8a 55 ?? 80 f2 76 2a 14 31 8b 4d ?? 8b 75 ?? 02 14 31 8b 5d ?? 81 c3 f4 bc 69 a0 8b 4d ?? 88 14 31 01 de 8b 5d e8 39 de 89 f9 89 75 ?? 89 4d ?? 89 7d ?? 0f 82 7a ff ff ff e9 00 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}