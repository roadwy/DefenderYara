
rule TrojanDownloader_Win32_Nuwar_B{
	meta:
		description = "TrojanDownloader:Win32/Nuwar.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {2f 63 6e 74 72 2e 70 68 70 3f } //2 /cntr.php?
		$a_01_1 = {73 76 63 70 2e 63 73 76 } //2 svcp.csv
		$a_00_2 = {36 34 2e 32 33 33 } //2 64.233
		$a_01_3 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //1 GetSystemDirectoryA
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_5 = {75 72 6c 6d 6f 6e 2e 64 6c 6c } //1 urlmon.dll
		$a_00_6 = {67 61 67 61 67 61 72 61 64 69 6f } //2 gagagaradio
		$a_00_7 = {77 69 6e 73 75 62 2e 78 6d 6c 00 57 69 6e 64 6f 77 73 53 75 62 56 65 72 73 69 6f 6e 00 00 55 52 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2) >=10
 
}