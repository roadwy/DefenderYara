
rule TrojanDownloader_Win32_Delf_NO{
	meta:
		description = "TrojanDownloader:Win32/Delf.NO,SIGNATURE_TYPE_PEHSTR,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 00 76 00 73 00 73 00 72 00 76 00 2e 00 65 00 78 00 65 00 20 00 2d 00 72 00 75 00 6e 00 73 00 65 00 72 00 69 00 76 00 63 00 65 00 } //2 cvssrv.exe -runserivce
		$a_01_1 = {00 00 53 00 74 00 61 00 62 00 69 00 6c 00 69 00 7a 00 65 00 64 00 00 00 } //2
		$a_01_2 = {2f 00 64 00 31 00 2e 00 7a 00 69 00 70 00 } //1 /d1.zip
		$a_01_3 = {77 00 64 00 62 00 2e 00 64 00 6c 00 6c 00 } //1 wdb.dll
		$a_01_4 = {77 00 64 00 63 00 2e 00 64 00 6c 00 6c 00 } //1 wdc.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}