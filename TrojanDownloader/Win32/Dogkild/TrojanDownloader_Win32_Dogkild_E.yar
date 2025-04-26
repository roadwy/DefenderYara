
rule TrojanDownloader_Win32_Dogkild_E{
	meta:
		description = "TrojanDownloader:Win32/Dogkild.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //1 if exist "%s" goto Repeat
		$a_01_1 = {70 63 69 64 75 6d 70 } //1 pcidump
		$a_01_2 = {5c 5c 2e 5c 70 63 69 64 75 6d 70 } //1 \\.\pcidump
		$a_01_3 = {75 70 64 61 74 65 7e 2e 65 78 65 } //1 update~.exe
		$a_01_4 = {5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 \rundll32.exe
		$a_01_5 = {5f 75 6f 6b 2e 62 61 74 } //1 _uok.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}