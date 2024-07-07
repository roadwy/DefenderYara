
rule TrojanDownloader_Win32_AsyncRAT_E_MTB{
	meta:
		description = "TrojanDownloader:Win32/AsyncRAT.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 43 6c 69 65 6e 74 31 2e 62 69 6e } //2 C:\windows\temp\Client1.bin
		$a_01_1 = {46 69 6c 65 20 44 6f 77 6e 6c 6f 61 64 65 72 } //2 File Downloader
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}