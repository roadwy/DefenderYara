
rule TrojanDownloader_Win32_Namaneat_A{
	meta:
		description = "TrojanDownloader:Win32/Namaneat.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {30 04 39 80 34 39 3c 80 34 39 8c 80 34 39 7c 80 34 39 4c 41 81 f9 db 0a 00 00 75 e4 } //2
		$a_01_1 = {eb 6e c7 85 28 fd ff ff 07 00 01 00 8d 85 28 fd ff ff 50 ff b5 d8 fc ff ff ff 93 29 19 00 10 85 c0 74 4d } //2
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 64 72 69 76 65 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 66 69 6c 65 2f 64 2f } //1 https://drive.google.com/file/d/
		$a_01_3 = {30 42 35 78 70 4a 43 6b 4d 4d 48 75 5f 56 57 77 31 56 57 46 78 51 6d 64 56 4e 6b 55 2f 76 69 65 77 3f 70 72 65 66 3d 32 26 70 6c 69 3d 31 } //1 0B5xpJCkMMHu_VWw1VWFxQmdVNkU/view?pref=2&pli=1
		$a_01_4 = {25 54 45 4d 50 25 } //1 %TEMP%
		$a_01_5 = {5c 6c 70 6d 2e 65 78 65 } //1 \lpm.exe
		$a_01_6 = {2f 63 2e 70 68 70 3f 61 64 64 3d } //1 /c.php?add=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}