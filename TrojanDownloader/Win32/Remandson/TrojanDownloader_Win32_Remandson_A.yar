
rule TrojanDownloader_Win32_Remandson_A{
	meta:
		description = "TrojanDownloader:Win32/Remandson.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6a 03 6a 04 8d 8e 9c 2a 00 00 51 c6 44 24 } //2
		$a_01_1 = {83 c7 01 3b fd 7c f5 85 f6 75 04 33 c0 eb 12 8b c6 8d 50 01 } //2
		$a_01_2 = {8d 44 24 4c 83 c4 04 8d bb a8 2a 00 00 8d 68 01 8a 08 83 c0 01 84 c9 75 f7 2b c5 } //1
		$a_01_3 = {4d 53 35 6a 62 79 35 72 63 69 39 74 62 32 52 31 } //1 MS5jby5rci9tb2R1
		$a_01_4 = {31 2e 63 6f 2e 6b 72 2f 6d } //1 1.co.kr/m
		$a_01_5 = {61 48 52 30 63 44 6f 76 4c 7a 45 78 4d 54 41 77 4d 43 35 6a 62 79 35 72 63 69 39 6a 62 33 56 75 } //1 aHR0cDovLzExMTAwMC5jby5rci9jb3Vu
		$a_01_6 = {31 31 31 30 30 30 2e 63 6f 2e 6b 72 2f 63 6f 75 6e } //1 111000.co.kr/coun
		$a_01_7 = {63 69 39 6a 62 33 56 75 64 43 39 70 62 6e 4e 6c 63 6e 51 75 63 47 68 77 50 33 42 70 } //1 ci9jb3VudC9pbnNlcnQucGhwP3Bp
		$a_01_8 = {75 6e 74 2f 69 6e 73 65 72 74 2e 70 68 70 3f 70 69 64 } //1 unt/insert.php?pid
		$a_01_9 = {5b 43 4f 55 4e 54 5d 00 69 65 78 70 6c 6f 72 65 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=6
 
}