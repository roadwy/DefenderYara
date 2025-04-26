
rule TrojanDownloader_Win32_Delf_ZWR{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZWR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2f 6e 65 77 ?? 73 2e 34 68 64 6e 2e 63 6f 6d 3a 35 30 30 31 2f 63 6f 6d 6d 64 6c 6c 2e 64 6c 6c } //1
		$a_01_1 = {14 00 00 00 5c 73 74 61 72 74 5c 44 4e 46 63 68 69 6e 61 73 2e 65 78 65 00 } //1
		$a_01_2 = {17 00 00 00 5c 73 74 61 72 74 5c 44 4e 46 43 6f 6d 70 6f 6e 65 6e 74 2e 44 4c 4c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}