
rule TrojanDownloader_Win32_Zegost_E_bit{
	meta:
		description = "TrojanDownloader:Win32/Zegost.E!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 10 32 d3 02 d3 88 10 40 4e 75 f4 } //2
		$a_03_1 = {8b 54 24 04 8a 1c 11 80 c3 ?? 88 1c 11 8b 54 24 04 8a 1c 11 80 f3 ?? 88 1c 11 41 3b c8 7c e1 } //2
		$a_03_2 = {4b c6 44 24 ?? 52 c6 44 24 ?? 4e c6 44 24 ?? 4c c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=3
 
}