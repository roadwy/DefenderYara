
rule TrojanDownloader_Win32_Matcash_F{
	meta:
		description = "TrojanDownloader:Win32/Matcash.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 ff d7 6a 90 01 01 ff d6 8d 85 90 01 02 ff ff 68 90 01 01 77 40 00 50 ff d7 6a 90 01 01 ff d6 8d 85 90 01 02 ff ff 68 90 01 01 77 40 00 50 ff d7 6a 90 01 01 ff d6 8d 85 90 01 02 ff ff 68 90 01 01 77 40 00 50 ff d7 6a 90 01 01 ff d6 8d 85 90 01 02 ff ff 68 90 01 01 77 40 00 50 ff d7 6a 90 01 01 ff d6 8d 85 90 01 02 ff ff 68 90 01 01 77 40 00 50 ff d7 6a 90 01 01 ff d6 90 00 } //1
		$a_02_1 = {68 74 74 70 3a 2f 2f 79 6d 71 2e 61 90 09 1c 00 6d 2f 31 37 50 90 02 05 2e 63 6f 90 02 05 6f 6f 90 02 05 63 62 90 02 05 2e 77 72 73 2e 6d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}