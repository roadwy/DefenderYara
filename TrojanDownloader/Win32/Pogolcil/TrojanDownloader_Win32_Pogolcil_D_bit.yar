
rule TrojanDownloader_Win32_Pogolcil_D_bit{
	meta:
		description = "TrojanDownloader:Win32/Pogolcil.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 07 33 d2 b9 0a 00 00 00 f7 f1 b8 cd cc cc cc 83 c3 01 80 c2 30 88 54 33 ff f7 27 c1 ea 03 85 d2 89 17 77 db 8b 45 ec 8d 4b ff 8b d1 2b d0 83 fa 01 7c 22 0f b6 14 31 30 14 30 8a 14 30 30 14 31 8a 14 31 30 14 30 83 e9 01 83 c0 01 8b d1 2b d0 83 fa 01 7d de } //1
		$a_01_1 = {83 7d d8 7a 7e 06 83 45 ec 02 eb 1f 8a 45 0f b2 0a f6 ea 8b 55 e4 8a c8 8b 45 ec 02 4c 10 02 80 e9 30 83 c0 03 88 4d 0f } //1
		$a_01_2 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 8d 8d 94 fe ff ff 51 52 ff d0 85 c0 89 85 84 fe ff ff 0f 84 a2 01 00 00 6a 79 68 4a e7 80 06 68 0d 0c 7e 1e 33 c0 68 df ae 25 07 68 75 1a 02 06 68 15 47 7d 00 } //1
		$a_01_3 = {45 78 69 74 50 72 6f 63 65 73 73 00 4c 6f 63 61 6c 20 41 70 70 57 69 7a 61 72 64 2d 47 65 6e 65 72 61 74 65 64 20 41 70 70 6c 69 63 61 74 69 6f 6e 73 00 00 44 42 00 00 49 4e 46 4f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}