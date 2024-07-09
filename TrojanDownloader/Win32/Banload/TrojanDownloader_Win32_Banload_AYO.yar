
rule TrojanDownloader_Win32_Banload_AYO{
	meta:
		description = "TrojanDownloader:Win32/Banload.AYO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 34 73 68 61 72 65 64 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 54 5a 44 5a 7a 32 52 42 62 61 2f 61 54 75 62 65 57 44 39 2e 65 78 65 } //1 http://www.4shared.com/download/TZDZz2RBba/aTubeWD9.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 34 73 68 61 72 65 64 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 2d 75 2d 5a 63 76 79 66 63 65 2f 53 6b 79 4c 69 6e 65 76 35 2e 65 78 65 } //1 http://www.4shared.com/download/-u-Zcvyfce/SkyLinev5.exe
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 34 73 68 61 72 65 64 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 70 4a 68 61 69 7a 51 67 62 61 2f 77 64 31 31 2e 65 78 65 } //1 https://www.4shared.com/download/pJhaizQgba/wd11.exe
		$a_03_3 = {6a ff 6a 00 e8 ?? ?? ?? ff 8b d8 68 88 13 00 00 53 e8 ?? ?? ?? ff 3d 02 01 00 00 75 07 6a 00 e8 ?? ?? ?? ff 5b c3 4b 42 32 38 32 33 33 32 34 30 78 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*2) >=3
 
}