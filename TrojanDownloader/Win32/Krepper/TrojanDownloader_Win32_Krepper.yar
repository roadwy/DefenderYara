
rule TrojanDownloader_Win32_Krepper{
	meta:
		description = "TrojanDownloader:Win32/Krepper,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0a 00 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b 20 6f 66 66 2c 20 62 75 64 64 79 } //5 fuck off, buddy
		$a_01_1 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 2e 68 74 61 } //3 C:\Documents and Settings\All Users\Start Menu\Programs\Startup\Microsoft Office.hta
		$a_01_2 = {43 3a 5c 77 65 62 2e 65 78 65 } //2 C:\web.exe
		$a_01_3 = {35 33 32 31 45 33 37 38 2d 46 46 41 44 2d 34 39 39 39 2d 38 43 36 32 2d 30 33 43 41 38 31 35 35 46 30 42 33 7d 5c 56 65 72 73 69 6f 6e 49 6e 64 65 70 65 6e 64 65 6e 74 50 72 6f 67 49 44 } //3 5321E378-FFAD-4999-8C62-03CA8155F0B3}\VersionIndependentProgID
		$a_01_4 = {26 70 72 6f 67 72 61 6d 3d 37 26 76 61 72 69 61 62 6c 65 3d 63 68 65 63 6b 26 76 61 6c 75 65 3d } //2 &program=7&variable=check&value=
		$a_01_5 = {26 70 72 6f 67 72 61 6d 3d 37 26 76 61 72 69 61 62 6c 65 3d 67 65 74 } //2 &program=7&variable=get
		$a_01_6 = {74 72 61 66 66 2d 73 74 6f 72 65 2e 63 6f 6d 2f 67 61 6c 6c 65 72 79 73 70 6f 6e 73 6f 72 2f 78 70 73 79 73 74 65 6d 2f } //2 traff-store.com/gallerysponsor/xpsystem/
		$a_01_7 = {61 66 66 63 67 69 2f 6f 6e 6c 69 6e 65 2e 66 63 67 69 3f 25 41 43 43 4f 55 4e 54 25 } //2 affcgi/online.fcgi?%ACCOUNT%
		$a_01_8 = {61 66 66 69 6c 69 61 74 65 2f 69 6e 74 65 72 66 61 63 65 2e 70 68 70 3f 75 73 65 72 69 64 3d } //2 affiliate/interface.php?userid=
		$a_01_9 = {6d 6d 2e 65 78 65 20 6d 6d 34 2e 65 78 65 20 25 41 43 43 4f 55 4e 54 25 } //2 mm.exe mm4.exe %ACCOUNT%
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2) >=17
 
}