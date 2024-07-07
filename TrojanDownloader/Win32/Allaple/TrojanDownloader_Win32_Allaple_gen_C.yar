
rule TrojanDownloader_Win32_Allaple_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Allaple.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 61 6b 61 77 69 6e 2e 63 6f 6d } //1 http://akawin.com
		$a_01_1 = {68 74 74 70 3a 2f 2f 66 78 2d 64 61 74 65 2e 63 6f 6d } //1 http://fx-date.com
		$a_01_2 = {68 74 74 70 3a 2f 2f 74 65 61 6d 2d 61 6d 65 72 69 63 61 2e 31 30 30 77 65 62 73 70 61 63 65 2e 6e 65 74 2f 67 6c 2e 70 68 70 3f 69 64 3d 31 } //1 http://team-america.100webspace.net/gl.php?id=1
		$a_01_3 = {69 6e 73 74 61 6c 6c 2e 65 78 65 00 ff ff ff ff 09 00 00 00 63 73 72 73 73 2e 65 78 65 00 00 00 ff ff ff ff 0d 00 00 00 74 6d 70 64 6f 77 6e 33 33 2e 64 6c 6c } //3
		$a_01_4 = {68 74 74 70 3a 2f 2f 61 67 2e 63 61 2e 67 6f 76 2f 63 6d 73 5f 70 64 66 73 2f 70 72 65 73 73 2f 4e 31 34 37 38 5f 43 6f 6d 70 6c 61 69 6e 74 41 54 26 54 55 6e 61 75 74 68 6f 72 69 7a 65 64 43 68 61 72 67 65 73 46 49 4e 41 4c 5f 54 42 46 32 2e 70 64 66 00 00 00 00 ff ff ff ff 11 00 00 00 63 3a 5c 46 49 4e 41 4c 5f 54 42 46 32 2e 70 64 66 } //3
		$a_01_5 = {63 6f 6f 6b 69 65 73 2e 74 78 74 00 ff ff ff ff 17 00 00 00 6d 79 73 71 6c 34 2d 76 68 2e 61 6d 65 6e 77 6f 72 6c 64 2e 63 6f 6d } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2) >=6
 
}