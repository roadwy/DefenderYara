
rule TrojanDownloader_Win32_Zegost_C{
	meta:
		description = "TrojanDownloader:Win32/Zegost.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b ?? 7c } //1
		$a_03_1 = {50 51 c6 44 24 ?? 4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 35 c6 44 24 ?? 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}