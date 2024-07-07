
rule TrojanDownloader_Win32_Small_CAA{
	meta:
		description = "TrojanDownloader:Win32/Small.CAA,SIGNATURE_TYPE_PEHSTR_EXT,16 00 15 00 07 00 00 "
		
	strings :
		$a_00_0 = {75 72 6c 6d 6f 6e 2e 64 6c 6c 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 43 3a 5c 00 25 58 00 00 55 8b ec 83 ec 48 } //20
		$a_00_1 = {47 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 41 } //1 GetVolumeInformationA
		$a_00_2 = {4e 53 50 53 74 61 72 74 75 70 } //1 NSPStartup
		$a_02_3 = {73 1e 8b 45 90 01 01 03 45 90 01 01 0f b6 00 8b 4d 90 01 01 83 c1 58 33 4d 90 01 01 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb d3 90 00 } //10
		$a_00_4 = {25 00 73 00 5c 00 6c 00 73 00 70 00 25 00 63 00 25 00 63 00 25 00 63 00 2e 00 64 00 6c 00 6c 00 } //10 %s\lsp%c%c%c.dll
		$a_00_5 = {57 53 43 49 6e 73 74 61 6c 6c 4e 61 6d 65 53 70 61 63 65 } //1 WSCInstallNameSpace
		$a_00_6 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 57 } //1 GetTempFileNameW
	condition:
		((#a_00_0  & 1)*20+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=21
 
}