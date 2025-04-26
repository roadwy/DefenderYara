
rule TrojanDownloader_Win32_WebToos_A{
	meta:
		description = "TrojanDownloader:Win32/WebToos.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {8d 4f ff 83 c4 10 33 c0 85 c9 7e 11 8a 14 30 80 c2 77 80 f2 19 88 14 30 40 3b c1 7c ef } //4
		$a_01_1 = {75 70 6c 6f 61 64 69 74 65 6d 00 00 6e 6f 70 61 73 73 77 64 } //1
		$a_01_2 = {47 6c 6f 62 61 6c 5c 79 6d 67 61 6d 65 75 70 64 61 74 65 } //1 Global\ymgameupdate
		$a_01_3 = {55 50 44 41 54 45 44 41 54 41 00 00 57 69 6e 64 6f 77 73 20 75 70 64 61 74 65 } //1
		$a_01_4 = {46 49 44 44 4c 45 52 2e 45 58 45 00 48 54 54 50 41 4e 41 4c 59 5a 45 52 53 54 44 56 33 2e 45 58 45 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}