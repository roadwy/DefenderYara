
rule TrojanDownloader_Win32_Stration_CC{
	meta:
		description = "TrojanDownloader:Win32/Stration.CC,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {47 45 54 20 2f 64 66 72 67 33 32 2e 65 78 65 20 48 54 54 50 2f 31 2e 31 } //10 GET /dfrg32.exe HTTP/1.1
		$a_02_1 = {68 74 74 70 3a 2f 2f 90 05 40 03 61 2d 7a 2e 63 6f 6d 2f 64 66 72 67 33 32 2e 65 78 65 90 00 } //10
		$a_02_2 = {48 6f 73 74 3a 20 90 05 40 03 61 2d 7a 2e 63 6f 6d 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10) >=30
 
}