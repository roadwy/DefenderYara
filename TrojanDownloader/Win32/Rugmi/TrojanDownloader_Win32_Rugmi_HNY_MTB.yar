
rule TrojanDownloader_Win32_Rugmi_HNY_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 f8 8b 0f 8d 47 04 8b 10 83 c0 04 [0-ff] [0-ff] [0-ff] 66 0f be 04 08 [0-ff] c6 44 24 ?? 01 ff (d2|d7) } //5
		$a_03_1 = {0f be 11 03 55 f8 89 55 f8 8b 45 f8 83 c0 01 50 [0-ff] [0-ff] 50 ff 95 74 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}