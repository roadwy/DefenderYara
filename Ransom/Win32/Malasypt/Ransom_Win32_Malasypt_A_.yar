
rule Ransom_Win32_Malasypt_A_{
	meta:
		description = "Ransom:Win32/Malasypt.A!!Malasypt.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_80_0 = {6d 6f 6d 73 62 65 73 74 66 72 69 65 6e 64 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d 20 6f 72 20 74 6f 72 72 65 6e 74 74 72 61 63 6b 65 72 40 69 6e 64 69 61 2e 63 6f 6d } //momsbestfriend@protonmail.com or torrenttracker@india.com  4
		$a_80_1 = {73 65 6e 64 20 6d 65 20 61 20 6d 65 73 73 61 67 65 20 61 74 20 42 4d 2d 4e 42 76 7a 4b 45 59 38 72 61 44 42 4b 62 39 47 70 31 78 5a 4d 52 51 70 65 55 35 73 76 77 67 32 } //send me a message at BM-NBvzKEY8raDBKb9Gp1xZMRQpeU5svwg2  4
		$a_80_2 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 6e 6f 77 20 65 6e 63 72 79 70 74 65 64 2e 20 49 20 68 61 76 65 20 74 68 65 20 6b 65 79 20 74 6f 20 64 65 63 72 79 70 74 20 74 68 65 6d 20 62 61 63 6b 2e } //Your files are now encrypted. I have the key to decrypt them back.  4
		$a_01_3 = {c7 00 6e 00 74 00 c7 40 04 64 00 6c 00 c7 40 08 6c 00 00 00 } //2
		$a_03_4 = {6a 09 50 ff 35 90 01 04 8d 05 90 01 04 03 05 90 01 04 8b 00 ff d0 0b c0 74 31 ff 75 08 e8 90 01 02 ff ff 40 8b c8 d1 e1 8d 45 fc 6a 00 50 51 ff 75 08 ff 35 90 01 04 8d 05 90 01 04 03 05 90 01 04 8b 00 ff d0 90 00 } //4
		$a_01_5 = {d1 e0 c7 04 10 2a 00 2e 00 c6 44 10 04 2a ff 75 fc ff 75 f8 } //2
		$a_01_6 = {75 1e 83 7f 2c 2e 74 18 81 7f 2c 2e 00 2e 00 74 0f } //2
		$a_01_7 = {74 6e 8b f8 ff 76 08 8f 47 08 ff 76 04 8f 47 04 ff 36 8f 07 } //2
		$a_03_8 = {66 8b 04 8a 66 3d 90 01 02 74 0c 66 3d 90 01 02 74 06 66 3d 90 01 02 75 09 c7 45 f4 01 00 00 00 eb 06 41 3b 4d f8 75 db ff 75 fc 90 00 } //4
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4+(#a_80_2  & 1)*4+(#a_01_3  & 1)*2+(#a_03_4  & 1)*4+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_03_8  & 1)*4) >=10
 
}