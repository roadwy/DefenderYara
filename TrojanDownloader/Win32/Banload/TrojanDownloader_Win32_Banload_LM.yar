
rule TrojanDownloader_Win32_Banload_LM{
	meta:
		description = "TrojanDownloader:Win32/Banload.LM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 24 6a 10 b9 90 01 04 ba 90 01 04 a1 90 01 04 8b 00 e8 90 01 04 a1 90 01 04 8b 00 e8 90 01 04 8d 55 fc a1 90 01 04 8b 00 e8 90 01 04 8b 45 fc ba 06 00 00 00 e8 90 01 04 6a 00 6a 00 8d 45 f8 e8 90 00 } //1
		$a_01_1 = {43 3a 5c 7a 55 70 74 50 69 74 75 2e 64 74 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}