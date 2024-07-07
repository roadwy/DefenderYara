
rule TrojanDownloader_Win32_Delf_GG{
	meta:
		description = "TrojanDownloader:Win32/Delf.GG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 70 65 6e 20 77 77 77 2e 61 73 30 38 2e 63 6f 6d 0d 0a 61 73 30 38 0d 0a 38 38 38 0d 0a 67 65 74 20 63 61 6c 63 2e 6a 70 67 0d 0a 62 79 65 00 ff d8 ff e0 } //1
		$a_01_1 = {66 74 70 20 2d 73 3a 51 2e 64 61 74 0d 0a 63 6c 73 0d 0a 63 61 6c 63 2e 6a 70 67 0d 0a 64 65 6c 20 51 2e 64 61 74 0d 0a 64 65 6c 20 25 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}