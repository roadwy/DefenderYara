
rule TrojanDownloader_Win64_Rugmi_HNH_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 10 8a 00 48 8b 4c 24 08 88 01 48 8b 44 24 08 48 83 c0 01 48 89 44 24 08 48 8b 44 24 10 48 83 c0 01 48 89 44 24 10 } //1
		$a_01_1 = {48 89 54 24 08 48 89 4c 24 10 48 8b 44 24 10 48 89 04 24 48 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}