
rule Trojan_Win32_Cryptinject_DG{
	meta:
		description = "Trojan:Win32/Cryptinject.DG,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 10 8b 4d 0c 8b 55 08 8b 74 24 30 8b 7c 24 34 83 f8 00 89 44 24 28 89 4c 24 24 89 54 24 20 89 74 24 1c 89 7c 24 18 0f 84 90 00 00 00 e9 80 00 00 00 8b 44 24 14 b9 85 10 42 08 89 44 24 10 f7 e1 8b 44 24 10 29 d0 d1 e8 01 d0 c1 e8 04 89 c1 c1 e1 05 29 c1 f7 d9 8b 44 24 10 0f b6 8c 08 a8 42 40 00 c7 44 24 34 00 00 00 00 c7 44 24 30 5c 00 cc 14 89 e2 89 4a 0c 89 42 08 8b 4c 24 24 89 4a 04 8b 74 24 20 89 32 e8 e7 ea ff ff c7 44 24 34 00 00 00 00 c7 44 24 30 00 00 00 00 8b 44 24 10 83 c0 01 8b 4c 24 28 39 c8 89 44 24 14 74 0d } //1
		$a_01_1 = {8b 44 24 10 b1 ae 8a 54 24 17 28 d1 88 4c 24 27 8a 4c 04 34 0f be f1 66 89 f7 66 89 7c 44 54 83 c0 01 83 f8 20 89 44 24 10 74 c1 eb d3 } //1
		$a_01_2 = {8b 45 d8 8b 4d e0 8b 55 dc 89 45 cc 89 55 c8 89 4d c4 0f 31 89 d6 89 c7 0f 31 89 d3 89 c1 b8 67 d9 bd 0a 66 8b 55 f2 66 81 c2 ec 24 66 89 55 f2 8b 55 e8 29 f9 8b 7d cc 83 ff 00 8b 7d c4 0f 44 f9 89 45 c0 8b 45 cc 83 f8 00 8b 45 c8 0f 44 c1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}