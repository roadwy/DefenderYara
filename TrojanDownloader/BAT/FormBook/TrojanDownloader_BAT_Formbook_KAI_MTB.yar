
rule TrojanDownloader_BAT_Formbook_KAI_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 1c 72 f3 ?? ?? 70 7e ?? ?? ?? 04 2b ?? 2b ?? 2b ?? 74 ?? ?? ?? 1b 2b ?? 2b ?? 2b ?? 2a 28 ?? ?? ?? 06 2b ?? 6f ?? ?? ?? 0a 2b e2 } //1
		$a_03_1 = {16 2d 1a 2b ?? 2b ?? 2b ?? 91 6f 25 00 00 0a } //1
		$a_03_2 = {07 6f 26 00 00 0a 0a 06 13 ?? 16 2d c7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}