
rule PWS_Win32_Wowsteal_gen_C{
	meta:
		description = "PWS:Win32/Wowsteal.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 08 00 00 "
		
	strings :
		$a_00_0 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //10 InternetReadFile
		$a_00_1 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //10 InternetOpenUrlA
		$a_03_2 = {b8 65 78 65 00 8b 35 ?? ?? ?? ?? 89 45 f8 89 45 c8 8d 45 f0 33 db 50 c7 45 f0 33 36 30 54 ff 75 08 c7 45 f4 72 61 79 2e 89 5d fc c7 45 c0 33 36 30 53 c7 45 c4 61 66 65 2e 89 5d cc ff d6 } //1
		$a_01_3 = {c7 45 d0 76 65 72 63 50 c7 45 d4 6c 73 69 64 ff 75 08 89 5d dc c7 45 e0 45 78 70 6c c7 45 e4 6f 72 65 72 89 5d ec ff d6 } //1
		$a_01_4 = {c7 85 3c ff ff ff 6e 5c 53 68 c7 85 40 ff ff ff 65 6c 6c 53 c7 85 44 ff ff ff 65 72 76 69 c7 85 48 ff ff ff 63 65 4f 62 c7 85 4c ff ff ff 6a 65 63 74 c7 85 50 ff ff ff 44 65 6c 61 c7 85 54 ff ff ff 79 4c 6f 61 c7 85 58 ff ff ff 64 00 00 00 } //1
		$a_01_5 = {c7 45 dc 65 72 4e 61 50 c7 45 e0 6d 65 00 00 89 5d e4 c7 45 e8 4c 61 73 74 c7 45 ec 4e 61 6d 65 89 5d f0 c7 45 b0 2e 5c 65 63 c7 45 b4 74 5c 68 6f c7 45 b8 6d 65 2e 69 c7 45 bc 6e 69 00 00 } //1
		$a_01_6 = {c7 45 c8 3f 62 3d 25 c7 45 cc 73 26 63 3d c7 45 d0 25 73 26 65 c7 45 d8 66 3d 25 73 c7 45 dc 26 69 3d 25 c7 45 e0 73 26 6b 3d c7 45 e4 25 73 26 6d c7 45 ec 6e 3d 25 73 89 75 f0 } //1
		$a_01_7 = {33 db c7 45 e4 54 41 32 45 c7 45 e8 64 69 74 00 89 5d ec c7 45 d4 54 46 72 6d c7 45 d8 4c 6f 67 4f c7 45 dc 6e 00 00 00 89 5d e0 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=22
 
}