
rule TrojanDownloader_Win32_AutoHK_C{
	meta:
		description = "TrojanDownloader:Win32/AutoHK.C,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 72 6c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 2c 20 68 74 74 70 73 3a 2f 2f 75 70 6c 6f 61 64 2e 63 61 74 } //4 UrlDownloadToFile, https://upload.cat
		$a_01_1 = {46 72 6f 6d 62 61 73 65 36 34 53 74 72 69 6e 67 28 27 54 27 2b 27 56 27 2b 27 71 27 2b 27 51 27 2b 27 41 27 2b 27 41 27 2b 27 4d 27 } //2 Frombase64String('T'+'V'+'q'+'Q'+'A'+'A'+'M'
		$a_01_2 = {52 75 6e 57 61 69 74 20 70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 65 78 69 74 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 20 25 50 57 53 63 72 69 70 74 25 20 2c 2c 20 68 69 64 65 } //1 RunWait powershell -noexit -windowstyle hidden  %PWScript% ,, hide
		$a_01_3 = {52 75 6e 57 61 69 74 20 25 41 70 70 64 61 74 61 25 5c 4d 69 63 72 6f 73 6f 66 74 } //1 RunWait %Appdata%\Microsoft
		$a_01_4 = {68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 56 72 38 33 54 39 73 35 } //1 https://pastebin.com/raw/Vr83T9s5
		$a_01_5 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //1 Microsoft\Windows\Start Menu\Programs\Startup
		$a_01_6 = {5c 57 69 6e 64 6f 77 73 5c 77 69 6e 64 6f 77 32 2e 76 62 73 22 20 2f 46 2c 2c 20 68 69 64 65 } //1 \Windows\window2.vbs" /F,, hide
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}