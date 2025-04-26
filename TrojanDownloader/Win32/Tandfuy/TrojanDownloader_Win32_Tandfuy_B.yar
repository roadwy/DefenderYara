
rule TrojanDownloader_Win32_Tandfuy_B{
	meta:
		description = "TrojanDownloader:Win32/Tandfuy.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 04 b2 ?? 8a 01 84 c0 74 0e 32 c2 88 01 8a 41 01 41 fe ca 84 c0 75 f2 c3 } //1
		$a_03_1 = {85 f6 89 74 24 ?? 75 05 5e 83 c4 ?? c3 8b 44 24 ?? 53 6a 00 6a 00 6a 00 6a 00 50 56 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}