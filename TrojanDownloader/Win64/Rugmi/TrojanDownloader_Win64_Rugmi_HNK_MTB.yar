
rule TrojanDownloader_Win64_Rugmi_HNK_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 54 24 10 48 89 4c 24 08 48 83 ec 18 48 8b 44 24 20 48 89 04 24 48 8b 44 24 28 48 89 44 24 08 48 8b 44 24 28 48 ff c8 48 89 44 24 28 48 83 7c 24 08 00 76 14 48 8b 04 24 c6 00 00 48 8b 04 24 48 ff c0 48 89 04 24 eb cd 48 8b 44 24 20 48 83 c4 18 c3 } //1
		$a_03_1 = {4c 8b c1 33 d2 48 8b c8 ff 15 ?? ?? ?? 00 48 89 44 24 ?? 48 8b 44 24 ?? 8b 40 ?? 8b c0 8b d0 48 8b 4c 24 ?? e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}