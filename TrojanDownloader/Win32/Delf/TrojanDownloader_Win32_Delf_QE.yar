
rule TrojanDownloader_Win32_Delf_QE{
	meta:
		description = "TrojanDownloader:Win32/Delf.QE,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2f 6d 6f 6e 74 61 67 65 2e 6a 70 67 90 0a 50 00 ff ff ff ff 09 00 00 00 73 65 74 75 70 2e 65 78 65 00 00 00 ff ff ff ff 2c 00 00 00 68 74 74 70 3a 2f 2f 64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}