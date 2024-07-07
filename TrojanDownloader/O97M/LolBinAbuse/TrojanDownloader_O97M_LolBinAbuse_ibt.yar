
rule TrojanDownloader_O97M_LolBinAbuse_ibt{
	meta:
		description = "TrojanDownloader:O97M/LolBinAbuse!ibt,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 09 00 00 "
		
	strings :
		$a_00_0 = {6d 73 68 74 61 2e 65 78 65 20 6a 61 76 61 73 63 72 69 70 74 3a 67 65 74 6f 62 6a 65 63 74 } //1 mshta.exe javascript:getobject
		$a_00_1 = {52 65 67 69 73 74 65 72 2d 43 69 6d 70 72 6f 76 69 64 65 72 2e 65 78 65 20 2d 70 61 74 68 20 63 3a } //1 Register-Cimprovider.exe -path c:
		$a_00_2 = {66 6f 72 66 69 6c 65 73 20 2f 70 } //1 forfiles /p
		$a_00_3 = {43 3a 5c 57 69 6e 64 6f 77 73 20 2f 6d 20 6e 6f 74 65 70 61 64 2e 65 78 65 20 2f 63 } //1 C:\Windows /m notepad.exe /c
		$a_00_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 72 65 70 6c 61 63 65 2e 65 78 65 20 } //1 C:\Windows\System32\cmd.exe /c replace.exe 
		$a_00_5 = {53 79 73 74 65 6d 33 32 5c 72 65 70 6c 61 63 65 2e 65 78 65 } //1 System32\replace.exe
		$a_00_6 = {63 6d 64 2e 65 78 65 20 2f 63 20 63 65 72 74 75 74 69 6c 2e 65 78 65 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 } //1 cmd.exe /c certutil.exe -urlcache -split -f
		$a_00_7 = {6d 73 69 65 78 65 63 2e 65 78 65 20 2f 71 20 2f 69 } //1 msiexec.exe /q /i
		$a_00_8 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 52 65 67 69 73 74 65 72 2d 43 69 6d 50 72 6f 76 69 64 65 72 2e 65 78 65 20 2d 70 61 74 68 } //1 C:\Windows\System32\Register-CimProvider.exe -path
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=2
 
}