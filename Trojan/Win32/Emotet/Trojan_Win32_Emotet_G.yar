
rule Trojan_Win32_Emotet_G{
	meta:
		description = "Trojan:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 33 e8 00 00 00 00 83 04 24 05 cb 4c 8b 55 08 41 8b 42 3c } //1
		$a_03_1 = {8a 04 16 32 81 90 01 04 41 88 02 83 f9 90 01 01 72 02 90 00 } //1
		$a_01_2 = {c6 00 e9 8b d7 2b 54 24 30 81 c6 ff 0f 00 00 83 ea 55 89 50 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_G_2{
	meta:
		description = "Trojan:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f7 f1 8a 0c 15 90 01 04 89 7c 24 90 01 01 8b 54 24 90 01 01 8a 2c 1a 8b 7c 24 90 01 01 8b 54 24 90 01 01 29 d7 89 7c 24 90 01 01 28 cd 80 f5 90 01 01 8b 7c 24 90 01 01 89 7c 24 90 01 01 8b 54 24 90 01 01 88 2c 1a 01 f3 89 5c 24 90 01 01 8b 74 24 90 01 01 39 f3 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_G_3{
	meta:
		description = "Trojan:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {79 09 81 ce 00 30 00 00 89 70 25 80 7c 24 90 01 01 00 75 44 8a 4c 24 90 01 01 80 c1 27 80 f9 06 90 00 } //1
		$a_01_1 = {69 c9 0d 66 19 00 0f be d2 40 8d 8c 11 5f f3 6e 3c 8a 10 84 d2 75 e9 } //1
		$a_03_2 = {bf 37 7e 13 a4 90 13 64 a1 30 00 00 00 8b 48 0c 56 8b 71 0c 83 7e 18 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_G_4{
	meta:
		description = "Trojan:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 25 49 92 24 f7 e6 2b f2 d1 ee 03 f2 c1 ee 03 56 } //1
		$a_01_1 = {25 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 6d 00 73 00 64 00 62 00 25 00 78 00 2e 00 65 00 78 00 65 00 } //10 %s\Microsoft\msdb%x.exe
		$a_01_2 = {0f b6 1c 0a 33 de 69 db 01 01 01 01 41 8b f3 3b c8 72 ed 5b } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=21
 
}
rule Trojan_Win32_Emotet_G_5{
	meta:
		description = "Trojan:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 04 16 32 81 90 01 04 41 88 02 83 f9 90 04 01 03 08 2d 0c 72 02 33 c9 42 83 ed 01 75 e7 90 00 } //1
		$a_01_1 = {0f b6 1c 0a 33 de 69 db 01 01 01 01 41 8b f3 3b c8 72 ed 5b } //1
		$a_03_2 = {41 66 0f b6 c0 66 89 04 56 83 f9 08 72 02 33 c9 8a 81 90 01 04 32 82 90 01 04 41 66 0f b6 c0 66 89 44 56 02 83 f9 08 72 02 33 c9 83 c2 02 83 fa 0e 72 bf 90 00 } //1
		$a_03_3 = {79 09 81 ce 00 30 00 00 89 70 25 80 7c 24 90 01 01 00 75 44 8a 4c 24 90 01 01 80 c1 27 80 f9 06 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_G_6{
	meta:
		description = "Trojan:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {35 83 2c 17 04 bb ff ff 00 00 f7 f3 8b c1 35 8a 89 ff c4 52 8b d1 81 f2 ae 75 70 6b 52 33 d2 f7 f3 8b c1 35 db 8b 81 a4 52 33 d2 f7 f3 8b c1 35 cb cc 7b 9b 81 f1 3d ed bc 3b 52 33 d2 f7 f3 } //10
		$a_03_1 = {8a 1c 17 32 99 90 01 04 41 88 1a 83 f9 15 72 02 33 c9 8a 1c 2a 32 99 90 01 04 41 88 5a 01 83 f9 15 72 02 33 c9 8a 1c 10 32 99 90 01 04 41 88 5a 02 83 f9 15 72 02 33 c9 90 00 } //10
		$a_03_2 = {79 09 81 ce 00 30 00 00 89 70 25 80 7c 24 90 01 01 00 75 44 8a 4c 24 90 01 01 80 c1 27 80 f9 06 90 00 } //1
		$a_01_3 = {25 00 73 00 5c 00 7b 00 25 00 30 00 38 00 58 00 2d 00 25 00 30 00 34 00 58 00 2d 00 25 00 30 00 34 00 58 00 2d 00 25 00 30 00 34 00 58 00 2d 00 25 00 30 00 38 00 58 00 25 00 30 00 34 00 58 00 7d 00 2e 00 65 00 78 00 65 00 } //1 %s\{%08X-%04X-%04X-%04X-%08X%04X}.exe
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}