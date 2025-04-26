
rule TrojanSpy_Win32_Agent_BP{
	meta:
		description = "TrojanSpy:Win32/Agent.BP,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 09 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_01_1 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //10 GetClipboardData
		$a_01_2 = {47 65 74 4f 70 65 6e 46 69 6c 65 4e 61 6d 65 41 } //10 GetOpenFileNameA
		$a_01_3 = {46 74 70 50 75 74 46 69 6c 65 41 } //10 FtpPutFileA
		$a_01_4 = {68 74 74 70 3a 2f 2f 6b 6f 6b 6f 76 73 2e 63 63 2f 70 6f 72 6e 6f 2f 73 74 61 74 2e 70 68 70 } //1 http://kokovs.cc/porno/stat.php
		$a_01_5 = {3f 6e 69 63 6b 3d } //1 ?nick=
		$a_01_6 = {26 69 6e 66 6f 3d 69 42 61 6e 6b 32 } //1 &info=iBank2
		$a_01_7 = {53 6f 66 74 77 61 72 65 5c 4a 61 76 61 53 6f 66 74 5c 50 72 65 66 73 } //1 Software\JavaSoft\Prefs
		$a_01_8 = {6c 6f 67 6f 2e 70 6e 67 } //1 logo.png
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=44
 
}