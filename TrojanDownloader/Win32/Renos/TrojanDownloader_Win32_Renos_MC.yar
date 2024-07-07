
rule TrojanDownloader_Win32_Renos_MC{
	meta:
		description = "TrojanDownloader:Win32/Renos.MC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d ff ff 7b 31 a3 90 01 04 c7 45 90 01 01 0a 00 00 00 c6 85 90 01 02 ff ff 2d c6 85 90 01 02 ff ff 2d c6 85 90 01 02 ff ff 5f c6 85 90 01 02 ff ff 2d c6 85 90 01 02 ff ff 22 c6 85 90 01 02 ff ff 38 c6 85 90 01 02 ff ff 32 c6 85 90 01 02 ff ff 34 c6 85 90 01 02 ff ff 71 90 00 } //1
		$a_03_1 = {83 f8 ff 0f 85 90 01 04 53 56 6a 03 53 6a 03 57 8d 85 90 01 02 ff ff 50 8d 85 90 01 02 ff ff 50 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}