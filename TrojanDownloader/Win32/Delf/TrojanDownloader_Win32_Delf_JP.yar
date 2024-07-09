
rule TrojanDownloader_Win32_Delf_JP{
	meta:
		description = "TrojanDownloader:Win32/Delf.JP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {61 6c 43 6c 69 65 6e 74 0d 4c 69 6e 65 73 2e 53 74 72 69 6e 67 73 [0-10] 2e 65 78 65 [0-04] 68 74 74 70 3a 2f 2f 72 65 70 6f 72 74 65 73 32 30 31 2e 63 6f 6d 2f [0-20] 2e 65 78 65 } //1
		$a_02_1 = {48 6c 69 6e 6b 4e 61 76 69 67 61 74 65 53 74 72 69 6e 67 00 ?? 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}