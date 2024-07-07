
rule TrojanDownloader_Win32_Zegost_D{
	meta:
		description = "TrojanDownloader:Win32/Zegost.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 10 32 d3 02 d3 88 10 40 4e 75 f4 } //1
		$a_01_1 = {8b 57 50 8b 47 34 6a 04 68 00 20 00 00 52 50 ff d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}