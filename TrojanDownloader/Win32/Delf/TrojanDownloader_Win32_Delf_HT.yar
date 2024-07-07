
rule TrojanDownloader_Win32_Delf_HT{
	meta:
		description = "TrojanDownloader:Win32/Delf.HT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 00 00 68 74 74 70 3a 2f 2f 77 77 77 2e 73 65 6c 65 63 74 74 68 6f 72 6f 75 67 68 62 72 65 64 73 2e 63 6f 6d 2f 6d 65 64 69 61 2f 6b 6c 2e 67 69 66 00 43 3a 5c 52 75 6e 64 64 6c 33 32 2e 65 78 65 } //1
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 72 66 77 70 2e 6f 72 67 2f 69 6d 61 67 65 73 2f 64 6c 6b 31 2e 67 69 66 00 00 00 00 43 3a 5c 57 69 6e 6d 73 67 72 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}