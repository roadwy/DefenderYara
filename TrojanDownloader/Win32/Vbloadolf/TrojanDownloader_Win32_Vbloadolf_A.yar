
rule TrojanDownloader_Win32_Vbloadolf_A{
	meta:
		description = "TrojanDownloader:Win32/Vbloadolf.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 65 74 20 62 53 74 72 6d 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 } //Set bStrm = CreateObject  1
		$a_00_1 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 20 00 43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 33 00 33 00 74 00 65 00 72 00 66 00 64 00 2e 00 76 00 62 00 73 00 } //1 wscript.exe C:\TEMP\33terfd.vbs
		$a_80_2 = {2f 62 6f 78 2f 61 72 63 68 69 76 6f 2e 65 78 65 } ///box/archivo.exe  1
		$a_02_3 = {53 61 76 65 54 6f 46 69 6c 65 [0-30] 2e 65 78 65 } //1
		$a_00_4 = {5c 00 45 00 4f 00 46 00 5c 00 41 00 6c 00 66 00 72 00 65 00 64 00 6f 00 5c 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //2 \EOF\Alfredo\Downloader\Project1.vbp
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*2) >=5
 
}