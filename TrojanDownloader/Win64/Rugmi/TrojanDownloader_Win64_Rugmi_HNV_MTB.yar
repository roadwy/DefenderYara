
rule TrojanDownloader_Win64_Rugmi_HNV_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.HNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 0f be 00 48 8b 4c 24 ?? 48 03 c8 48 8b c1 48 89 44 24 90 1b 00 48 8b 44 24 90 1b 00 48 ff c0 48 8b c8 ff 94 24 [0-02] 00 00 48 89 84 24 } //2
		$a_03_1 = {48 63 40 3c 48 (8b 40 2c|[0-60] 8b 40 2c )} //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}