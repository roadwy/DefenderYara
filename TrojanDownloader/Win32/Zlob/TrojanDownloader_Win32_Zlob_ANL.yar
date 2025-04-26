
rule TrojanDownloader_Win32_Zlob_ANL{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANL,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_03_0 = {8a 47 01 47 3a c3 75 f8 be ?? ?? 40 00 66 a5 8d bd f0 fe ff ff 4f 8a 47 01 47 3a c3 75 f8 be ?? ?? 40 00 a5 a5 a5 a5 } //4
		$a_00_1 = {57 65 62 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 } //5 Web Technologies
		$a_00_2 = {61 77 65 72 25 64 2e 62 61 74 } //1 awer%d.bat
		$a_00_3 = {25 73 5c 6c 6c 25 73 25 64 2e 65 78 65 } //1 %s\ll%s%d.exe
		$a_00_4 = {6f 67 6c 65 2e } //1 ogle.
		$a_00_5 = {68 53 63 6f 70 65 73 } //1 hScopes
		$a_00_6 = {72 6d 64 69 72 20 22 25 73 22 } //1 rmdir "%s"
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=10
 
}