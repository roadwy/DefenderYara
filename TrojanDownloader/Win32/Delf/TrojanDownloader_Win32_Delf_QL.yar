
rule TrojanDownloader_Win32_Delf_QL{
	meta:
		description = "TrojanDownloader:Win32/Delf.QL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ba 01 00 00 00 8d 85 98 fa ff ff e8 90 01 04 e8 90 01 04 53 68 00 04 00 00 8d 85 e4 fb ff ff 50 8b 45 ec 50 e8 90 01 04 6a 00 8d 95 e4 fb ff ff 8b 0b 8d 85 98 fa ff ff e8 90 00 } //1
		$a_00_1 = {73 76 68 6f 73 74 73 2e 65 78 65 } //1 svhosts.exe
		$a_02_2 = {2f 61 72 71 75 69 76 6f 90 02 05 2e 7a 69 70 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}