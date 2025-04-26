
rule TrojanDownloader_Win32_Small_AAAC{
	meta:
		description = "TrojanDownloader:Win32/Small.AAAC,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {77 69 6e 6c 6f 67 61 6e 2e 65 78 65 } //2 winlogan.exe
		$a_02_1 = {68 74 74 70 3a 2f 2f 67 69 63 69 61 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 ?? 31 } //1
		$a_02_2 = {68 74 74 70 3a 2f 2f 6d 61 73 67 69 4f 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 ?? 31 } //1
		$a_02_3 = {68 74 74 70 3a 2f 2f 66 31 76 69 73 61 2e 69 6e 66 6f 2f 63 64 2f 63 64 2e 70 68 70 3f 69 64 3d 25 73 26 76 65 72 3d 67 ?? 31 } //1
		$a_00_4 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //1 OpenProcess
		$a_00_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_6 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //1 \drivers\etc\hosts
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}