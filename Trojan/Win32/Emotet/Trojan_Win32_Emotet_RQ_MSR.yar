
rule Trojan_Win32_Emotet_RQ_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RQ!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {d8 5c 0b 8b 42 30 f8 b3 75 3c 0c 3a 0a ff 33 b0 a2 75 e8 96 bb c0 cc 3f 71 95 96 66 7a 45 8c 99 80 e8 d6 fa 37 e3 d4 e6 87 dd f8 87 b6 4b 09 2f } //1
		$a_01_1 = {8b ec 83 c4 c0 53 68 12 47 85 38 e8 63 d4 ff ff 59 89 45 e0 68 47 98 b8 d4 e8 55 d4 ff ff 59 89 45 c0 68 b5 40 d7 a3 e8 47 d4 ff ff 59 89 45 c4 68 07 77 54 3b e8 39 d4 ff ff 59 89 45 e4 68 3f 92 31 19 e8 2b d4 ff ff 59 89 45 e8 68 c8 0d c5 f8 e8 1d d4 ff ff 59 89 45 ec 68 27 c2 44 e0 e8 0f d4 ff ff 59 } //1
		$a_01_2 = {6a 40 68 00 10 00 00 8b 55 0c 52 6a 00 ff 55 c0 8b d8 8b 45 0c 50 8b 55 08 52 53 ff 55 e0 83 c4 0c 8b 4d 0c 51 8d 45 0c 50 53 6a 00 6a 01 6a 00 8b 55 f4 52 ff 55 e4 85 c0 75 04 33 c0 eb 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_RQ_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.RQ!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 83 0c 02 00 00 33 d2 40 25 ff 00 00 00 89 83 0c 02 00 00 8a 14 03 8b 8b 10 02 00 00 03 d1 81 e2 ff 00 00 00 89 93 10 02 00 00 33 d2 8b 83 0c 02 00 00 8a 14 03 89 93 18 02 00 00 8b 8b 10 02 00 00 8b 93 0c 02 00 00 8a 04 0b 30 04 13 8b 8b 0c 02 00 00 8b 93 10 02 00 00 8a 04 0b 30 04 13 8b 8b 10 02 00 00 8b 93 0c 02 00 00 8a 04 0b 30 04 13 8b 8b 10 02 00 00 8a 83 18 02 00 00 88 04 0b ff 83 04 02 00 00 8b 93 04 02 00 00 81 fa 00 0c 00 00 0f 8c } //1
		$a_01_1 = {8b 8b 08 02 00 00 8a 14 03 0f b6 84 03 00 01 00 00 03 d1 03 d0 81 e2 ff 00 00 00 89 93 08 02 00 00 8b 83 04 02 00 00 8a 14 13 30 14 03 8b 93 04 02 00 00 8b 83 08 02 00 00 8a 0c 13 30 0c 03 8b 93 08 02 00 00 8b 83 04 02 00 00 8a 0c 13 30 0c 03 ff 83 04 02 00 00 8b 83 04 02 00 00 3d 00 01 00 00 7c 9a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}