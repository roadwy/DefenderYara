
rule TrojanSpy_Win32_Banker_AJO{
	meta:
		description = "TrojanSpy:Win32/Banker.AJO,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {7a 7a 63 30 4b 4c 30 52 7a 4f 45 42 77 43 41 62 4f 35 41 65 75 49 44 58 6d 42 } //1 zzc0KL0RzOEBwCAbO5AeuIDXmB
		$a_01_1 = {47 44 67 59 49 7a 62 36 54 6f 4b } //1 GDgYIzb6ToK
		$a_01_2 = {32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 } //1
		$a_01_3 = {47 42 20 50 6c 75 67 69 6e 20 49 6e 73 74 61 6c 61 64 6f 2e } //10 GB Plugin Instalado.
		$a_01_4 = {4d 61 71 75 69 6e 61 20 73 65 6d 20 41 6e 74 56 69 72 75 73 } //10 Maquina sem AntVirus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=21
 
}
rule TrojanSpy_Win32_Banker_AJO_2{
	meta:
		description = "TrojanSpy:Win32/Banker.AJO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {7a 7a 63 30 4b 4c 30 52 7a 4f 45 42 77 43 41 62 4f 35 41 65 75 49 44 58 6d 42 } //1 zzc0KL0RzOEBwCAbO5AeuIDXmB
		$a_01_1 = {47 44 67 59 49 7a 62 36 54 6f 4b 38 63 72 76 56 64 42 46 46 42 4d 54 52 4a 2f 78 6a 6c 62 50 61 59 69 59 64 73 53 4a 4b 4f 32 63 4b 39 69 7a 79 } //1 GDgYIzb6ToK8crvVdBFFBMTRJ/xjlbPaYiYdsSJKO2cK9izy
		$a_01_2 = {47 44 67 59 49 7a 62 36 54 6f 4b 38 68 57 44 2b 70 52 38 6b 63 4f 70 57 72 59 4e 41 65 6d 6e 4f 6e 2b 49 77 6c 58 72 37 64 58 41 76 4e 4d 41 79 32 2b 2b 70 44 32 77 33 } //1 GDgYIzb6ToK8hWD+pR8kcOpWrYNAemnOn+IwlXr7dXAvNMAy2++pD2w3
		$a_01_3 = {32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 } //1
		$a_01_4 = {8b 37 85 db 74 15 8a 02 3c 61 72 06 3c 7a 77 02 2c 20 88 06 42 46 4b } //1
		$a_01_5 = {0e 54 4b 65 79 50 72 65 73 73 45 76 65 6e 74 } //1
		$a_03_6 = {35 ae ca 7b c3 ff 25 90 01 04 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c 90 00 } //1
		$a_03_7 = {8b 0e 8b 1f 38 d9 75 90 01 01 4a 74 90 01 01 38 fd 75 90 01 01 4a 74 90 01 01 81 e3 00 00 ff 00 81 e1 00 00 ff 00 39 d9 75 90 00 } //1
		$a_03_8 = {eb 07 b2 02 e8 90 01 02 ff ff 8b 45 fc 80 78 5b 00 74 90 01 01 8b 45 fc 8b 40 44 80 b8 90 01 02 00 00 01 90 01 02 8b 90 01 01 fc 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1) >=5
 
}