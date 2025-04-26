
rule TrojanDownloader_Win32_Enstan_A{
	meta:
		description = "TrojanDownloader:Win32/Enstan.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 00 3c 00 74 ?? c1 0d ?? ?? 40 00 0d } //1
		$a_03_1 = {68 c7 69 9b fa 68 ?? ?? 40 00 e8 ?? ?? ff ff } //1
		$a_03_2 = {68 66 57 38 ef 68 ?? ?? 40 00 e8 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}