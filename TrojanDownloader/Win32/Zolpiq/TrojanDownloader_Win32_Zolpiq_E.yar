
rule TrojanDownloader_Win32_Zolpiq_E{
	meta:
		description = "TrojanDownloader:Win32/Zolpiq.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 eb 05 8d 34 8b 2b ee 60 8b 7c 8b fc 29 2c 37 e2 f7 61 5d 03 c6 ff e0 } //1
		$a_01_1 = {80 3b e9 74 0f 8b 44 24 14 c6 03 e9 2b c3 83 e8 05 89 43 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}