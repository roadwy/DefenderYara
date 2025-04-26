
rule TrojanDownloader_Win64_Rugmi_HNL_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 b8 00 10 00 00 ba 0a 02 00 00 33 c9 48 8b 84 24 ?? ?? 00 00 ff 50 } //1
		$a_03_1 = {00 48 8d 54 24 ?? 48 8d 4c 24 ?? 48 8b 84 24 ?? ?? 00 00 ff (50|10) } //1
		$a_03_2 = {ff 50 10 48 8b 84 24 ?? ?? 00 00 8b 4c 24 ?? 89 08 48 8d 4c 24 ?? e8 ?? ?? ?? ?? 89 44 24 ?? 48 8b 8c 24 ?? ?? 00 00 ff 51 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}