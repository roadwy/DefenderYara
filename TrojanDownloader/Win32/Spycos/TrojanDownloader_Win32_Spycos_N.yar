
rule TrojanDownloader_Win32_Spycos_N{
	meta:
		description = "TrojanDownloader:Win32/Spycos.N,SIGNATURE_TYPE_PEHSTR_EXT,13 00 12 00 09 00 00 09 00 "
		
	strings :
		$a_01_0 = {c1 ed 11 33 dd 03 c3 03 d8 8b e8 c1 e5 09 33 c5 03 d0 03 c2 8b ea c1 ed 03 } //09 00 
		$a_03_1 = {68 00 00 0a 00 6a 00 6a 00 68 90 01 01 00 00 00 6a 90 01 01 6a 00 6a 00 90 01 01 6a 00 b9 90 01 04 ba 90 01 04 b8 90 01 04 e8 90 01 04 a3 90 01 04 68 90 01 04 90 03 02 05 6a 64 68 90 01 01 00 00 00 6a 00 a1 90 01 04 50 e8 90 01 04 eb 0c 90 00 } //03 00 
		$a_01_2 = {3a 44 45 4c 42 41 54 } //01 00  :DELBAT
		$a_01_3 = {4d 35 53 65 31 56 53 51 43 37 43 6c 2f 32 30 39 47 4a 75 4d 76 4d 36 66 70 } //01 00  M5Se1VSQC7Cl/209GJuMvM6fp
		$a_01_4 = {34 73 78 58 76 4d 53 51 56 4f 53 6f 57 34 68 77 6b 7a 64 70 74 67 } //01 00  4sxXvMSQVOSoW4hwkzdptg
		$a_01_5 = {67 56 4e 68 43 44 33 47 6e 72 59 6a 6e 41 4b 33 58 4a 53 72 46 41 } //01 00  gVNhCD3GnrYjnAK3XJSrFA
		$a_01_6 = {48 41 51 76 34 53 5a 52 6a 4a 75 52 55 53 78 37 73 32 4c 37 34 41 3d 3d } //01 00  HAQv4SZRjJuRUSx7s2L74A==
		$a_01_7 = {50 46 6f 42 4c 2b 73 50 6d 4f 36 36 6a 4d 62 55 4a 55 4b 78 76 72 44 57 64 2f 33 73 6b 7a 5a 55 77 63 71 75 65 33 4c 42 4f 4f 30 74 57 6b 61 71 76 59 6a 78 48 78 73 53 57 30 44 54 42 35 68 57 66 46 79 4b 50 6f 6b 35 2f 6c 78 74 72 56 49 32 73 53 55 30 77 45 4a 6d 78 79 4f 39 51 78 6a 4e 72 63 4c 79 69 59 6b 69 44 62 55 3d } //01 00  PFoBL+sPmO66jMbUJUKxvrDWd/3skzZUwcque3LBOO0tWkaqvYjxHxsSW0DTB5hWfFyKPok5/lxtrVI2sSU0wEJmxyO9QxjNrcLyiYkiDbU=
		$a_01_8 = {78 7a 62 2b 73 4e 6f 33 52 69 75 41 62 62 56 4c 6e 4f 7a 6e 50 } //00 00  xzb+sNo3RiuAbbVLnOznP
	condition:
		any of ($a_*)
 
}