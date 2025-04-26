
rule TrojanDownloader_Win32_Adposhel_A{
	meta:
		description = "TrojanDownloader:Win32/Adposhel.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 f1 29 f9 89 d7 8b 55 d8 69 c9 ?? ?? ?? ?? 32 03 0f b6 c0 0f b6 80 ?? ?? ?? ?? 31 c1 88 0b 43 39 d3 0f 82 ?? ?? ?? ?? 47 } //1
		$a_03_1 = {0f b6 03 89 f1 29 d9 69 c9 ?? ?? ?? ?? 29 f9 0f b6 80 ?? ?? ?? ?? 31 c1 88 0b 43 39 d3 0f 82 ?? ?? ?? ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}