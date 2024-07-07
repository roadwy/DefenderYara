
rule TrojanDownloader_Win32_Zegost_C{
	meta:
		description = "TrojanDownloader:Win32/Zegost.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 11 80 c3 90 01 01 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 90 01 01 88 1c 11 41 3b 90 01 01 7c 90 00 } //1
		$a_03_1 = {50 51 c6 44 24 90 01 01 4b c6 44 24 90 01 01 6f c6 44 24 90 01 01 74 c6 44 24 90 01 01 68 c6 44 24 90 01 01 65 c6 44 24 90 01 01 72 c6 44 24 90 01 01 35 c6 44 24 90 01 01 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}