
rule TrojanDownloader_Win64_Rugmi_HNAB_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 10 8a 00 48 8b 4c 24 08 88 01 48 8b 44 24 08 48 83 c0 01 48 89 44 24 08 48 8b 44 24 10 48 83 c0 01 48 89 44 24 10 } //5
		$a_01_1 = {44 0f b6 4c 14 0c 44 30 09 } //5
		$a_03_2 = {89 c2 48 83 c1 01 44 0f b6 4c ?? ?? ?? ?? ?? 83 c0 01 83 } //5
		$a_01_3 = {48 69 c0 8a 00 00 00 } //1
		$a_03_4 = {48 63 41 3c [0-30] 88 00 00 00 [0-30] 8b ?? ?? 1c } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=7
 
}