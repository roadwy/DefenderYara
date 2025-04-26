
rule TrojanDownloader_Win32_Adload_L{
	meta:
		description = "TrojanDownloader:Win32/Adload.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 2e 66 6c 76 00 00 00 75 2e 62 6d 70 00 00 00 64 2e 65 78 65 00 00 00 72 2e 64 6c 6c 00 00 00 73 2e 64 6c 6c } //1
		$a_01_1 = {42 48 4f 2e 46 75 6e 50 6c 61 79 65 72 00 00 00 7b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}