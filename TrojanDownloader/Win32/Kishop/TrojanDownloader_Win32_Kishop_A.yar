
rule TrojanDownloader_Win32_Kishop_A{
	meta:
		description = "TrojanDownloader:Win32/Kishop.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 5b 64 69 72 73 78 36 34 5d 00 } //1
		$a_03_1 = {3b 45 0c 73 21 8b 45 ?? 8a 00 34 ?? 8b 4d ?? 88 01 8b 45 ?? 8a 00 34 ?? 8b 4d ?? 88 01 8b 45 ?? 40 89 45 ?? eb d0 c9 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}