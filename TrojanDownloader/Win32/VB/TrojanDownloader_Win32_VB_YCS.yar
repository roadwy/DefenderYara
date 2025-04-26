
rule TrojanDownloader_Win32_VB_YCS{
	meta:
		description = "TrojanDownloader:Win32/VB.YCS,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 6c 75 67 69 6e 41 64 6f 62 65 } //1 PluginAdobe
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_2 = {6d 00 6f 00 64 00 75 00 6c 00 6f 00 61 00 2e 00 73 00 77 00 66 00 } //1 moduloa.swf
		$a_00_3 = {53 00 57 00 53 00 65 00 74 00 5c 00 73 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //1 SWSet\setup.exe
		$a_02_4 = {55 00 73 00 65 00 72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 [0-70] 5c 00 6e 00 65 00 77 00 32 00 39 00 31 00 31 00 2e 00 76 00 62 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}